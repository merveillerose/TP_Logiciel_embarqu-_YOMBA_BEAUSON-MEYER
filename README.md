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
Assurez-vous d'avoir [Rust et Cargo](https://rustup.rs/) installés sur votre machine.

```
# Cloner le projet
git clone https://github.com/merveillerose/TP_Logiciel_embarqu-_YOMBA_BEAUSON-MEYER.git

# Accéder au dossier
cd TP_Logiciel_embarqu-_YOMBA_BEAUSON-MEYER

# Compiler le projet
cargo build --release
````
Nous avons enregistré chaque étape dans le **bin**.
Pour lancer le programme final qui se trouve dans le fichier partie5.rs, écrivez ces lignes dans le terminal :
```
cargo run --bin partie5 -- --pcap [CHEMIN_FICHIER] --packet-count [NB_PAQUETS] --output-format [json/csv]

```

### Exemple de commandes
* Analyse simple :
```
cargo run --bin partie5 -- --pcap capture-23-05-08-ttgo.pcapng
```

* Analyse complète avec export CSV :
```
cargo run --bin partie5 -- --pcap capture-23-05-08-ttgo.pcapng -P 100 -F csv -o resultats.csv
```
