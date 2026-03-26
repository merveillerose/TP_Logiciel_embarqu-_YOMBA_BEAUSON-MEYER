use clap::Parser;
use pcap::Capture;
use network_analyzer::{DroneResult, analyser_tlv, sauvegarder_resultats};

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
            sauvegarder_resultats(&drone_records, &args.output_format, &args.output_file);
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