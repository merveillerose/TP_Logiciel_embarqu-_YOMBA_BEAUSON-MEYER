# Détection de drone sur le réseau

Dans le cadre de notre TP de Logiciel Embarqué Sécurisé, nous avons mené une analyse de trames réseaux pour retrouver des drones.
L'objectif était d'identifier les trames Wifi d'identification et de localisation de drones et extraire les informations pertinentes de ces trames à l'aide d'un programme en Rust.  

## Fonctionnalités
* **Analyse de fichiers PCAP/PCAPNG** : Lecture des trames via la bibliothèque `pcap`.
* **Décodage 802.11** : Extraction des trames Beacon et analyse des champs *Vendor Specific* (OUI `6a:5c:35`).
* **Extraction de données** : Récupération de l'identifiant du drone, de sa position GPS (Latitude, Longitude), de son altitude et de sa vitesse.
* **Sauvegarde multi-format** : Export des résultats en **JSON** ou **CSV** grâce à la bibliothèque `serde`.
* **Architecture modulaire** : Séparation de la logique de décodage dans une bibliothèque (`lib.rs`) pour une meilleure maintenabilité.

## Installation
Il faut s'assurer d'avoir Rust et Cargo (https://rustup.rs/) installés sur votre machine.

```
# Cloner le projet
git clone https://github.com/merveillerose/TP_Logiciel_embarqu-_YOMBA_BEAUSON-MEYER.git

# Accéder au dossier
cd TP_Logiciel_embarqu-_YOMBA_BEAUSON-MEYER

# Compiler le projet
cargo build --release
````

Nous avons enregistré chaque étape dans le **bin** : 
* Dans `partie3.rs` vous trouverez le code permettant l'identification des trames de type **beacon** correspondant aux trames DroneID et l'extraction des données pertinentes de ces trames.
* `partie4.rs`: nous avons ajouté la fonctionnalité de sauvegarde des résultats dans un fichier. L'utilisateur peut désormais spécifier le format de sortie (JSON, CSV) et le nom du fichier de sortie via des arguments de ligne de commande.

Le programme final se trouve dans le fichier `partie5.rs`, écrivez ces lignes dans le terminal pour le lancer :
```
cargo run --bin partie5 -- --pcap [CHEMIN_FICHIER] --packet-count [NB_PAQUETS] --output-format [json/csv]
```

### Exemple de commandes
* Analyse simple de 10 paquets, enregistrement automatique des résultats dans un fichier **JSON** nommé `results.json`:
```
cargo run --bin partie5 -- --pcap capture-23-05-08-ttgo.pcapng --packet-count 10
```
