use clap::Parser;
use pcap::Capture;

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

fn main() {
    // Analyse des arguments de la ligne de commande
    let args = Args::parse();


    if let Some(pcap_path) = args.pcap {

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
                        analyser_tlv(&data[tlv_start..], mac_str);
                    }
                }
            }
        }

        println!("Analyse terminée. {} paquets traités.", count - 1);    

    } else if let Some(iface) = args.interface {
        println!("Capture en temps réel sur : {} ({} paquets)", iface, args.packet_count);
    } else {
        println!("Erreur, veuillez spécifier soit --pcap soit --interface !!!");
    }
}

fn analyser_tlv(mut data: &[u8], mac_addr: String) {
    let mut ssid = String::from("<Inconnu>");

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
                    
                    // La charge utile commence après OUI et VS Type
                    decoder_val_drone(&tag_value[4..]);
                }
            },
            _ => {}
        }
        data = &data[2 + tag_len..];
    }
    // Affichage final pour chaque Beacon
    println!("(Trame BEACON) MAC: {} | SSID: {}", mac_addr, ssid);
}

fn decoder_val_drone(mut ch_utile: &[u8]) {
    // On parcourt les sous-TLV du drone
    while ch_utile.len() >= 2 {
        let val_type = ch_utile[0];
        let val_len = ch_utile[1] as usize;
        if ch_utile.len() < 2 + val_len { break; }
        let val = &ch_utile[2..2 + val_len];

        match val_type {
            0x02 => { // Identifiant FR sur 30 caractères
                println!("ID Drone : {}", String::from_utf8_lossy(val).trim());
            },
            0x04 => { // Latitude (4 octets signés)
                if val_len == 4 {
                    let lat = i32::from_be_bytes([val[0], val[1], val[2], val[3]]) as f64 / 10_000_000.0;
                    println!("Latitude  : {:.7}°", lat);
                }
            },
            0x05 => { // Longitude (4 octets signés)
                if val_len == 4 {
                    let lon = i32::from_be_bytes([val[0], val[1], val[2], val[3]]) as f64 / 10_000_000.0;
                    println!("Longitude : {:.7}°", lon);
                }
            },
            0x06 => { // Altitude (2 octets signés)
                if val_len == 2 {
                    let alt = i16::from_be_bytes([val[0], val[1]]);
                    println!("Altitude  : {} m", alt);
                }
            },
            0x0a => { // Vitesse horizontale (1 octet)
                println!("Vitesse   : {} m/s", val[0]);
            },
            _ => {} // On ignore les autres types pour l'instant
        }
        ch_utile = &ch_utile[2 + val_len..];
    }
}