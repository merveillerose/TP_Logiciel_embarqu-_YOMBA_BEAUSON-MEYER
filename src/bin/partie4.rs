use clap::Parser;
use pcap::Capture;
use serde::Serialize;
use std::fs::File;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Fichier PCAP à analyser
    #[arg(short, long, value_name = "FILE", conflicts_with = "interface")]
    pcap: Option<String>,

    /// Interface réseau pour la capture en temps réel
    #[arg(short, long, value_name = "INTERFACE")]
    interface: Option<String>,

    /// Afficher la liste des interfaces réseau disponibles et quitter
    #[arg(short,long)]
    cards: bool,

    /// Filtre de capture
    #[arg(short, long, value_name = "FILTER")]
    filter: Option<String>,

    /// Nombre de paquets à capturer
    #[arg(short='P',long, default_value_t = 10)]
    packet_count: u32,

    /// Format des résultats (json, csv)
    #[arg(short='F',long, default_value = "json")]
    output_format: String,

    /// Nom du fichier de sortie
    #[arg(short,long, default_value = "results.json")]
    output_file: String,
}

#[derive(Serialize, Clone)]
struct DroneResult {
    mac: String,
    ssid: String,
    id_drone: String,
    latitude: f64,
    longitude: f64,
    altitude: i16,
    vitesse: u8,
}

fn main() {
    // Analyse des arguments de la ligne de commande
    let args = Args::parse();
    let mut drone_records: Vec<DroneResult> = Vec::new();


    if let Some(ref pcap_path) = args.pcap {

        println!("Analyse du fichier : {}", pcap_path);

        // Ouverture du fichier PCAP
        let mut cap = Capture::from_file(pcap_path).expect("Erreur d'ouverture du fichier PCAP");
        
        let mut count = 0;

        // On lit chaque paquet un par un
        while let Ok(packet) = cap.next_packet() {

            count += 1;

            if count > args.packet_count { break; } // arrêt
            
            let data = packet.data; // octets bruts du paquet

            // Récupération de la taille de Radiotap
            if data.len() < 4 { continue; } // vérification longueur
            let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize; // conversion little endian

            // Le header 802.11 commence juste après le Radiotap
            if data.len() < radiotap_len + 1 { continue; } // vérification longueur
            let frame_control = data[radiotap_len];

            if frame_control == 0x80 { // 0x80 = Beacon
                
                // On extrait l'adresse MAC située à l'offset 10 de l'en-tête 802.11
                let mac_start = radiotap_len + 10;
                if data.len() >= mac_start + 6 {
                    let mac = &data[mac_start..mac_start + 6];
                    let mac_str = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                                          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    // On saute 24 (MAC) + 12 (Gestion fixe) octets pour le TLV
                    let tlv_start = radiotap_len + 24 + 12;
                    if data.len() > tlv_start {
                        if let Some(drone) = analyser_tlv(&data[tlv_start..], mac_str) {
                            drone_records.push(drone);
                        }
                    }
                }
            }
        }

        // On sauvegarde les resultats
        if !drone_records.is_empty() {
            sauvegarder_resultats(&drone_records, &args);
        } else {
            println!("Aucun drone détecté, aucun fichier créé.");
        }

        println!("Analyse terminée. {} paquets traités.", count - 1); 

    } 
    else if let Some(iface) = args.interface {
        println!("Capture en temps réel sur : {} ({} paquets)", iface, args.packet_count);
    } 
    else {
        println!("Erreur, veuillez spécifier soit --pcap soit --interface !!!");
    }  
}

fn analyser_tlv(mut data: &[u8], mac_addr: String) -> Option<DroneResult> {
    let mut ssid = String::from("<Inconnu>");
    let mut drone_trouve: Option<DroneResult> = None; // variable pour stocker le résultat

    while data.len() >= 2 {
        let tag_type = data[0];
        let tag_len = data[1] as usize;
        if data.len() < 2 + tag_len { break; }
        let tag_value = &data[2..2 + tag_len];

        match tag_type {
            0x00 => { // SSID
                ssid = String::from_utf8_lossy(tag_value).to_string();
            },
            0xdd => { // Vendor Specific
                // On vérifie le OUI (3 octets) + VS Type (1 octet)
                if tag_len >= 4 && &tag_value[0..4] == [0x6a, 0x5c, 0x35, 0x01] {
                    println!("\nDrone identifié (norme FR) - MAC: {}", mac_addr);
                    println!("SSID du point d'accès : {}", ssid);
                    
                    // On recupere les infos du drone
                    drone_trouve = decoder_val_drone(&tag_value[4..], mac_addr.clone(), ssid.clone());
                }
            },
            _ => {}
        }
        data = &data[2 + tag_len..];
    }
    // Affichage final pour chaque Beacon
    println!("(Trame BEACON) MAC: {} | SSID: {}", mac_addr, ssid);
   
    drone_trouve // on retourne le drone trouvé
}

fn decoder_val_drone(mut ch_utile: &[u8], mac: String, ssid: String)-> Option<DroneResult> {
    let mut drone_val = DroneResult {
        mac, ssid, id_drone: String::from("Inconnu"),
        latitude: 0.0, longitude: 0.0, altitude: 0, vitesse: 0,
    };
    
    // On parcourt les sous-TLV du drone
    while ch_utile.len() >= 2 {
        let val_type = ch_utile[0];
        let val_len = ch_utile[1] as usize;
        if ch_utile.len() < 2 + val_len { break; }
        let val = &ch_utile[2..2 + val_len];

        match val_type {
            0x02 => { // Identifiant FR sur 30 caractères
                let id = String::from_utf8_lossy(val).trim().to_string();
                println!("ID Drone : {}", id);
                drone_val.id_drone = id; // On enregistre le ID
            },
            0x04 => { // Latitude (4 octets signés)
                if val_len == 4 {
                    let lat = i32::from_be_bytes([val[0], val[1], val[2], val[3]]) as f64 / 10_000_000.0;
                    println!("Latitude  : {:.7}°", lat);
                    drone_val.latitude = lat; // On enregistre la latitude
                }
            },
            0x05 => { // Longitude (4 octets signés)
                if val_len == 4 {
                    let lon = i32::from_be_bytes([val[0], val[1], val[2], val[3]]) as f64 / 10_000_000.0;
                    println!("Longitude : {:.7}°", lon);
                    drone_val.longitude = lon; // On enregistre la longitude
                }
            },
            0x06 => { // Altitude (2 octets signés)
                if val_len == 2 {
                    let alt = i16::from_be_bytes([val[0], val[1]]);
                    println!("Altitude  : {} m", alt);
                    drone_val.altitude = alt; // On enregistre l'altitude
                }
            },
            0x0a => { // Vitesse horizontale (1 octet)
                println!("Vitesse   : {} m/s", val[0]);
                drone_val.vitesse = val[0]; // On enregistre la vitesse
            },
            _ => {} // On ignore les autres types
        }
        ch_utile = &ch_utile[2 + val_len..];
    }
    Some(drone_val)
}

fn sauvegarder_resultats(records: &Vec<DroneResult>, args: &Args) {
    let file = File::create(&args.output_file).expect("Erreur création fichier");
    
    match args.output_format.as_str() {
        "json" => {
            serde_json::to_writer_pretty(file, records).expect("Erreur JSON");
            println!("---> {} résultats sauvegardés dans {}", records.len(), args.output_file);
        },
        "csv" => {
            let mut wtr = csv::Writer::from_writer(file);
            for r in records {
                wtr.serialize(r).expect("Erreur CSV");
            }
            wtr.flush().unwrap();
            println!("---> {} résultats sauvegardés dans {}", records.len(), args.output_file);
        },
        _ => println!("!! Format non support !!"),
    }
}