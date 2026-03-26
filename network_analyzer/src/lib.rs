use serde::Serialize;
use std::fs::File;

#[derive(Serialize, Clone, Debug)]
pub struct DroneResult {
    pub mac: String,
    pub ssid: String,
    pub id_drone: String,
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: i16,
    pub vitesse: u8,
}

pub fn analyser_tlv(mut data: &[u8], mac_addr: String) -> Option<DroneResult> {
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

pub fn sauvegarder_resultats(records: &Vec<DroneResult>, format: &str, filename: &str) {
    let file = File::create(filename).expect("Erreur création fichier");
    
    match format {
        "json" => {
            serde_json::to_writer_pretty(file, records).expect("Erreur JSON");
            println!("---> {} résultats sauvegardés dans {}", records.len(), filename);
        }
        "csv" => {
            let mut wtr = csv::Writer::from_writer(file);
            for r in records {
                wtr.serialize(r).expect("Erreur CSV");
            }
            wtr.flush().unwrap();
            println!("---> {} résultats sauvegardés dans {}", records.len(), filename);
        },
        _ => println!("!! Format '{}' non supporter !!", format),
    }
}
