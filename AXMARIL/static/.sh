#!/bin/bash
# Demander à l'utilisateur quel dossier parent sous /etc/axmaril/ doit être créé
echo -n "Entrez le nom du dossier parent à créer pour installer axmaril: "
read parent_dir
echo -n "Entrez le chemin du fichier de conf: "
read conf_dir
echo -n "Entrez l'ip de l'hote:  "
read raft_hote
echo -n "Entrez les partenaire du cluster exemple: 10.0.0.25:5000,10.0.0.25:5000: "
read raft_partener
echo -n "Entrez le chemin ou se situe la license: "
read license

full_path="$parent_dir"
echo "Création du dossier : $full_path"
sudo mkdir -p "$full_path"
echo "Création du dossier : $full_path/db"
sudo mkdir -p "$full_path/db"
echo "Création du dossier : $full_path/data"
sudo mkdir -p "$full_path/data"
sudo mkdir -p "$full_path/file_keys"
AXMARIL_SERVICE_FILE="/etc/systemd/system/axmaril.service"

# Définir les variables
VARIABLES=(
    "AZUMARIL_INITIATOR_DBPATH=\"$full_path/db\""
    "RAFT_HOST=\"$raft_hote\""
    "RAFT_PARTNERS=\"$raft_partener\""
    "LICENSE_FILE_PATH=\"$license\""
)

# Pour chaque variable, vérifier si elle est déjà présente dans ~/.bashrc
for VAR in "${VARIABLES[@]}"; do
    VARIABLE_NAME=$(echo "$VAR" | cut -d'=' -f1)
    export $VAR
    # Vérifier si la variable est déjà dans ~/.bashrc
done


# Déplacer le fichier binaire vers /usr/local/bin et lui donner les droits d'exécution
echo "Déplacement du fichier binaire et configuration des permissions..."
sudo mv /home/ubuntu/axmaril /usr/local/bin/axmaril
sudo chmod a+x /usr/local/bin/axmaril

# Demander le nombre de clés et le seuil minimal pour le déverrouillage
echo -n "Entrez le nombre total de clés : "
read maxkeys
echo -n "Entrez le nombre minimal de clés requis pour déverrouiller l'application : "
read minkeys

# Lancer l'application en arrière-plan
echo "Lancement de l'application Axmaril..."
axmaril --start-cluster &

# Attendre un moment pour s'assurer que l'application démarre correctement
sleep 25
curl -k -i -X POST https://localhost:54321/initialise \
  -H "Content-Type: application/json" \
  -d "{\"minkey\":$minkeys,\"maxkey\":$maxkeys}" \
  > /"$full_path"/file_keys/log.txt
# Extraire les clés du fichier log.txt
keys=$(grep -oP '"keys":\[\K[^\]]+' /"$full_path"/file_keys/log.txt)
# Initialiser une liste Bash
key_list=()
# Ajouter chaque clé extraite dans la liste
IFS=',' # Définir la virgule comme séparateur
for key in $keys; do
    key=$(echo $key | sed 's/^"//;s/"$//')
    key_list+=("\"$key\"")
done

# Afficher les clés pour vérifier
echo "Clés extraites:"
for k in "${key_list[@]}"; do
    echo "$k"
done
echo "lites des clés : ${key_list[@]}"

# Sélectionner uniquement les clés nécessaires pour l'unseal
selected_keys=("${key_list[@]:0:$minkeys}")

#echo "listes des clés selectionnée: ${selected_key[@]}s"

# Préparer le JSON avec les clés pour le curl
keys_json=$(printf '%s,' "${selected_keys[@]}")
keys_json="[${keys_json%,}]" # Supprimer la dernière virgule


#chagement de la configuration 
curl -k -i -X POST https://localhost:54321/config \
  -H "Content-Type: application/json" \
  -d "{\"keys\":$keys_json,\"oneFile\":true,\"config_data\":$config_data}"





echo "clés pour unseal: $keys_json"
# Exécuter la commande curl
curl -k -i -X POST https://localhost:54321/unseal \
  -H "Content-Type: application/json" \
  -d "{\"keys\":$keys_json,\"oneFile\":false,\"config_data\":{\"\":\"\"}}"
#données de configuration
config_data=$(cat $conf_dir)

keys_for_service=()
for key in "${selected_keys[@]}"; do
    # Enlever les guillemets
    cleaned_key=$(echo "$key" | sed 's/^"//;s/"$//')
    keys_for_service+=("$cleaned_key")
done

echo "cles : ${keys_for_service[@]}"

keys_=$(printf '%s,' "${keys_for_service[@]}")
service_keys="${keys_%,}"
#final_keys="\"${keys_json}\""
echo "cles3 : $service_keys"

# Arrêter tous les processus AXMARIL
pkill -9 axmaril
echo "Tous les processus AXMARIL arrêtés."

sleep 10

# Créer ou éditer le fichier de service
cat <<EOL > $AXMARIL_SERVICE_FILE
[Unit]
Description="Azumaril manage your cloud server"
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target

[Service]
#ProtectSystem=full
User=root
Environment="LICENSE_FILE_PATH=$license"
Environment="AZUMARIL_INITIATOR_DBPATH=$full_path/db"
Environment="AZUMARIL_KEYS=$service_keys"
Environment="RAFT_HOST=$raft_hote"
Environment="RAFT_PARTNERS=$raft_partener"
#PrivateTmp=yes
#PrivateDevices=yes
#SecureBits=keep-caps
ExecStart=/usr/local/bin/axmaril
#ExecStartPost=/home/ubuntu/ax_unseal.sh
ExecStop=pkill -9 axmaril
#ExecReload=/bin/kill --signal HUP $MAINPID
#KillMode=process
#KillSignal=SIGINT
#Restart=on-failure
#RestartSec=5
#TimeoutStopSec=80
#StartLimitInterval=80
#StartLimitBurst=3
#LimitNOFILE=65536
#LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOL

echo "Fichier de service AXMARIL créé ou modifié : $AXMARIL_SERVICE_FILE"

# Recharger les services systemd
systemctl daemon-reload
echo "Systemd rechargé."

# Démarrer et activer le service AXMARIL
systemctl start axmaril
systemctl enable axmaril
echo "Service AXMARIL démarré et activé pour le démarrage automatique."

echo "Déploiement d'AXMARIL terminé avec succès."

