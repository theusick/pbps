#!/bin/bash

# Отключаем вывод команд для безопасности
set +x

# Очистка пароля по завершению скрипта
cleanup() {
    unset LDAP_ADMIN_PASSWORD
}

# Устанавливаем trap для очистки при выходе из скрипта
trap cleanup EXIT

LDAP_DOMAIN="test-ldap"
LDAP_ZONE="ru"
LDAP_FULL_DOMAIN="$LDAP_DOMAIN.$LDAP_ZONE"

USER_NAME="test"
USER_PASSWORD="password"

BASE_DN="dc=$LDAP_DOMAIN,dc=$LDAP_ZONE"
ADMIN_DN="cn=admin,$BASE_DN"
PEOPLE_OU="ou=people,$BASE_DN"
GROUPS_OU="ou=groups,$BASE_DN"
USER_DN="uid=$USER_NAME,$PEOPLE_OU"

# Запрос пароля администратора LDAP
read -s -p "Введите пароль администратора LDAP: " LDAP_ADMIN_PASSWORD
echo

if [ -z "$LDAP_ADMIN_PASSWORD" ]; then
    echo "Ошибка: Пароль не может быть пустым" >2
    exit 1
fi

echo "Установка LDAP..."

# Установка пароля администратора LDAP
sudo debconf-set-selections <<< "slapd slapd/password1 password $LDAP_ADMIN_PASSWORD"
sudo debconf-set-selections <<< "slapd slapd/password2 password $LDAP_ADMIN_PASSWORD"

# Установка OpenLDAP
sudo apt-get update > /dev/null
sudo apt-get install -y slapd ldap-utils > /dev/null

# Настройка LDAP сервера
sudo debconf-set-selections <<< "slapd slapd/password1 password $LDAP_ADMIN_PASSWORD"
sudo debconf-set-selections <<< "slapd slapd/password2 password $LDAP_ADMIN_PASSWORD"
sudo debconf-set-selections <<< "slapd slapd/domain string $LDAP_FULL_DOMAIN"
sudo debconf-set-selections <<< "slapd shared/organization string Test Organization"
sudo debconf-set-selections <<< "slapd slapd/backend select MDB"
sudo debconf-set-selections <<< "slapd slapd/purge_database boolean true"
sudo debconf-set-selections <<< "slapd slapd/move_old_database boolean true"
sudo debconf-set-selections <<< "slapd slapd/allow_ldap_v2 boolean false"
sudo debconf-set-selections <<< "slapd slapd/no_configuration boolean false"

sudo dpkg-reconfigure -f noninteractive slapd > /dev/null

# Проверка успешности настройки slapd
if [ $? -ne 0 ]; then
    echo "Ошибка при настройке slapd."
    exit 1
fi

# Создание базовой структуры LDAP
cat <<EOL | sudo ldapadd -x -D $ADMIN_DN -w $LDAP_ADMIN_PASSWORD > /dev/null
dn: $PEOPLE_OU
objectClass: organizationalUnit
ou: people

dn: $GROUPS_OU
objectClass: organizationalUnit
ou: groups
EOL

if [ $? -ne 0 ]; then
    echo "Ошибка при создании базовой структуры LDAP."
    exit 1
fi

sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f ./scripts/add_authRealm.ldif > /dev/null

sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f ./scripts/add_customObject.ldif > /dev/null

# Создание пользователя
cat <<EOL | sudo ldapadd -x -D $ADMIN_DN -w $LDAP_ADMIN_PASSWORD > /dev/null
dn: $USER_DN
objectClass: inetOrgPerson
objectClass: customObject
uid: $USER_NAME
sn: User
givenName: Test
cn: Test User
displayName: Test User
userPassword: $(slappasswd -s $USER_PASSWORD)
authRealm: people@$LDAP_FULL_DOMAIN
userPasswordMD5: $(echo -n $USER_PASSWORD | base64)
EOL

config_path="./config/server.conf"

if [ -f "$config_path" ]; then
    sed -i '/^LDAP_BIND_PASS=/d' "$config_path"

    echo "LDAP_BIND_PASS=$LDAP_ADMIN_PASSWORD" >> "$config_path"
fi

if [ $? -eq 0 ]; then
    echo "LDAP сервер инициализирован и пользователь добавлен."
else
    echo "Ошибка при добавлении пользователя в LDAP."
fi
