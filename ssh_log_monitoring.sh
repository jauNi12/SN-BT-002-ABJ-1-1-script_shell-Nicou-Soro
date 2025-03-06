#!/bin/bash

# Configuration
LOG_FILE="/var/log/auth.log" #variable contenant les log a examiner
HOSTS_DENY="/etc/hosts.deny" #variable pour le fichier contenant les addresses bloquées
FAILED_ATTEMPTS_LIMIT=5 #variable pour spécifier le nombre de tentative echoué
TIME_PERIOD=10  #variable pour spécifier le temps de l'attaque en minutes
#EMAIL="nicouejaures003@gmail.com"  # variable pour mon adresse e-mail

# Pour envoyer une notification par e-mail mais necessite des configurations en local 
#send_notification() {
#    local ip=$1
#    local subject="Alerte de sécurité : Attaque par force brute détectée"
#    local message="L'IP $ip a été bloquée en raison de tentatives de connexion SSH échouées répétées."
#    echo "$message" | mail -s "$subject" "$EMAIL"
#}

# Analyser les logs SSH pour les tentatives de connexion échouées
analyze_logs() {
    echo "Analyse des logs SSH pour les tentatives de connexion échouées..."

    # Récupérer les IP avec plus de X échecs dans les Y dernières minutes
    suspicious_ips=$(grep "Failed password" "$LOG_FILE" | awk '{print $14}' | sort | uniq -c | awk -v limit="$FAILED_ATTEMPTS_LIMIT" '$1 > limit {print $2}')

    if [ -z "$suspicious_ips" ]; then
        echo "Aucune IP suspecte détectée."
    else
        echo "IP suspectes détectées :"
        echo "$suspicious_ips"

        # Bloquer les IP suspectes dans /etc/hosts.deny
        for ip in $suspicious_ips; do
            if ! grep -q "$ip" "$HOSTS_DENY"; then
                echo "sshd: $ip" >> "$HOSTS_DENY"
                echo "IP $ip bloquée dans /etc/hosts.deny."
#                send_notification "$ip"
            else
                echo "IP $ip est déjà bloquée."
            fi
        done
    fi
}

# Exécuter la fonction principale
analyze_logs
