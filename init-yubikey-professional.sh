#!/bin/bash -e

## Functions

function __usage() {
	echo "$0 usage:"
	grep "[[:space:]].) #" "$0" | sed -E 's/.*([a-zA-Z]).*\).*# (.*)/\t-\1    \2/'
}

function __settings() {
	echo -e "\nSettings:"
	echo -e "\tJANUS_DEBUG=$JANUS_DEBUG"
	echo -e "\tJANUS_VERBOSE=$JANUS_VERBOSE"
	echo -e "\tJANUS_FORCE=$JANUS_FORCE"
	echo -e "\tJANUS_DRYRUN=$JANUS_DRYRUN"

	echo -e "\tJANUS_HOSTNAME=$JANUS_HOSTNAME"
	echo -e "\tJANUS_MACHINES=$JANUS_MACHINES"

    echo -e "\tJANUS_NOEXPORT=$JANUS_NOEXPORT"
    echo -e "\tJANUS_NOBACKUP=$JANUS_NOBACKUP"
    echo -e "\tJANUS_INSECURE=$JANUS_INSECURE"
    echo -e "\tJANUS_TOUCH=$JANUS_TOUCH"

	echo -e "\tJANUS_ORG=$JANUS_ORG"
	echo -e "\tJANUS_DN=$JANUS_DN"

	echo -e "\tJANUS_USER_NAME=$JANUS_USER_NAME"
	echo -e "\tJANUS_USERNAME=$JANUS_USERNAME"

    echo -e "\tJANUS_EFI=$JANUS_EFI"
    echo -e "\tJANUS_EFI_FACTORY_SRC=$JANUS_EFI_FACTORY_SRC"
    echo -e "\tJANUS_CA=$JANUS_CA"
    echo -e "\tJANUS_CA_ROOT_PASSPHRASE=$JANUS_CA_ROOT_PASSPHRASE"
    echo -e "\tJANUS_CA_INTERMEDIATE_PASSPHRASE=$JANUS_CA_INTERMEDIATE_PASSPHRASE"
    echo -e "\tJANUS_GPG_PASSPHRASE=$JANUS_GPG_PASSPHRASE"
    echo -e "\tJANUS_LUKS_PASSPHRASE=$JANUS_LUKS_PASSPHRASE"

    echo -e "\tJANUS_GPG_IDENTITY=$JANUS_GPG_IDENTITY"
    echo -e "\tJANUS_GPG_KEYTYPE=$JANUS_GPG_KEYTYPE"
    echo -e "\tJANUS_GPG_EXPIRATION=$JANUS_GPG_EXPIRATION"
    echo -e "\tJANUS_GPG_ADMIN_PIN=$JANUS_GPG_ADMIN_PIN"
    echo -e "\tJANUS_GPG_USER_PIN=$JANUS_GPG_USER_PIN"
    echo -e "\tJANUS_GPG_USE_OTP=$JANUS_GPG_USE_OTP"

    echo -e "\tJANUS_PIV_PUK=$JANUS_PIV_PUK"
    echo -e "\tJANUS_PIV_PIN=$JANUS_PIV_PIN"
    echo -e "\tJANUS_PIV_MGM=$JANUS_PIV_MGM"
}

function __bip39() {
    local -a _words
    local -a _bytes
    local _csum=0

    readarray -t _words < <(curl -s https://raw.githubusercontent.com/bitcoin/bips/refs/heads/master/bip-0039/english.txt)
    readarray -t _bytes < <(LC_ALL=C tr -dc '01' < /dev/urandom | fold -w 11 | head -n 11)

    for _byte in "${_bytes[@]}"; do
        _byte=$((2#${_byte}))
        _csum=$((_csum + _byte + 1))
        echo -n "${_words[_byte]} "
    done

    _csum=$((_csum % 2048))
    echo -n "${_words[_csum]}"
}

function __cmd() {
	if [ "$JANUS_VERBOSE" = true ]; then
		echo "$@"
	fi

	if [ "$JANUS_DRYRUN" = false ]; then
		"$@"
	fi
}

function __kill_daemons() {
    __cmd pkill -9 gpg-agent || true
    __cmd pkill -9 scdaemon || true
    __cmd pkill -9 pcscd || true
}

function __reset_yubikey() {
    __kill_daemons

    read -p "Insert YubiKey and press [ENTER] to continue"
    sleep 2

    __cmd ykman fido reset -f
    __cmd ykman oath reset -f
    __cmd ykman hsmauth reset -f
    __cmd ykman openpgp reset -f
    __cmd ykman otp delete -f 1 || true
    __cmd ykman otp delete -f 2 || true
    __cmd ykman piv reset -f

    read -p "Remove YubiKey and press [ENTER] to continue"
    sleep 1

    __kill_daemons
}

function __init_passphrases() {
    if [ "$JANUS_LUKS_PASSPHRASE" = "_random_" ] ; then
        JANUS_LUKS_PASSPHRASE="$(__bip39)"
    fi

    if [ "$JANUS_CA_ROOT_PASSPHRASE" = "_random_" ] ; then
        JANUS_CA_ROOT_PASSPHRASE="$(__bip39)"
    fi

    if [ "$JANUS_CA_INTERMEDIATE_PASSPHRASE" = "_random_" ] ; then
        JANUS_CA_INTERMEDIATE_PASSPHRASE="$(__bip39)"
    fi

    if [ "$JANUS_GPG_USE_OTP" = true ]; then
        if [ ${#JANUS_GPG_PASSPHRASE} -gt 38 ]; then
            echo "GPG passphrase must be 38 characters or less to store in OTP" >&2
            exit 1
        fi
    elif [ "$JANUS_GPG_PASSPHRASE" = "_random_" ] ; then
        JANUS_GPG_PASSPHRASE="$(__bip39)"
    fi

    if [ "$JANUS_PIV_PASSPHRASE_9A" = "_random_" ] ; then
        JANUS_PIV_PASSPHRASE_9A="$(__bip39)"
    fi

    if [ "$JANUS_PIV_PASSPHRASE_9C" = "_random_" ] ; then
        JANUS_PIV_PASSPHRASE_9C="$(__bip39)"
    fi

    if [ "$JANUS_PIV_PASSPHRASE_9D" = "_random_" ] ; then
        JANUS_PIV_PASSPHRASE_9D="$(__bip39)"
    fi

    if [ "$JANUS_PIV_PASSPHRASE_9E" = "_random_" ] ; then
        JANUS_PIV_PASSPHRASE_9E="$(__bip39)"
    fi

    if [ "$JANUS_EFI_PASSPHRASE_PK" = "_random_" ] ; then
        JANUS_EFI_PASSPHRASE_PK="$(__bip39)"
    fi

    if [ "$JANUS_EFI_PASSPHRASE_KEK" = "_random_" ] ; then
        JANUS_EFI_PASSPHRASE_KEK="$(__bip39)"
    fi

    if [ "$JANUS_EFI_PASSPHRASE_USER" = "_random_" ] ; then
        JANUS_EFI_PASSPHRASE_USER="$(__bip39)"
    fi
}

function __init_yubikey() {
    read -p "Insert YubiKey and press [ENTER] to continue"
    sleep 2

    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping YubiKey initialization"
        return
    fi

    if [ "$JANUS_GPG_USE_OTP" = true ]; then
        if [ "$JANUS_GPG_PASSPHRASE" = "_random_" ] ; then
            ykman otp static --generate --keyboard-layout US --length 38 2
            read -p "Long press YubiKey button to continue" -s -r JANUS_GPG_PASSPHRASE
        else
            ykman otp static --keyboard-layout US 2 "$JANUS_GPG_PASSPHRASE"
        fi
    fi

    read -p "Remove YubiKey and press [ENTER] to continue"
    sleep 1

    __kill_daemons

    read -p "Insert YubiKey and press [ENTER] to continue"
    sleep 2

    {
        echo 3
        echo 12345678
        printf "%s\n" "$JANUS_GPG_ADMIN_PIN" "$JANUS_GPG_ADMIN_PIN"
        echo q
    } | gpg --command-fd=0 --pinentry-mode=loopback --change-pin

    {
        echo 1
        echo 123456
        printf "%s\n" "$JANUS_GPG_USER_PIN" "$JANUS_GPG_USER_PIN"
        echo q
    } | gpg --command-fd=0 --pinentry-mode=loopback --change-pin

    read -p "Remove YubiKey and press [ENTER] to continue"
    sleep 1

    __kill_daemons

    read -p "Insert YubiKey and press [ENTER] to continue"
    sleep 2

    {
        echo admin
        echo login
        echo "$JANUS_GPG_IDENTITY"
        echo "$JANUS_GPG_ADMIN_PIN"
        echo quit
    } | gpg --command-fd=0 --pinentry-mode=loopback --edit-card

    read -p "Remove YubiKey and press [ENTER] to continue"
    sleep 1

    __kill_daemons

    read -p "Insert YubiKey and press [ENTER] to continue"
    sleep 2

    if [ "$JANUS_TOUCH" = true ]; then
        ykman piv access change-management-key \
            --management-key "010203040506070801020304050607080102030405060708" \
            --algorithm AES256 \
            --touch \
            --new-management-key "$JANUS_PIV_MGM"
        echo "New MGM set."
    else
        ykman piv access change-management-key \
            --management-key "010203040506070801020304050607080102030405060708" \
            --algorithm AES256 \
            --new-management-key "$JANUS_PIV_MGM"
        echo "New MGM set."
    fi

    ykman piv access change-puk --puk 12345678 --new-puk "$JANUS_PIV_PUK"
    ykman piv access change-pin --pin 123456 --new-pin "$JANUS_PIV_PIN"

    read -p "Remove YubiKey and press [ENTER] to continue"
    sleep 1

    __kill_daemons

    read -p "Insert YubiKey and press [ENTER] to continue"
    sleep 2

    # Enable retired PIV slots via pkcs11
    # See: https://support.yubico.com/hc/en-us/articles/4585159896220-Troubleshooting-Retired-PIV-Slots-Unavailable-When-Accessing-via-PKCS11
    echo C10114C20100FE00 | 
    ykman piv objects import \
        --management-key "$JANUS_PIV_MGM" \
        --pin "$JANUS_PIV_PIN" \
        0x5FC10C <(echo -n "C10114C20100FE00")

    read -p "Remove YubiKey and press [ENTER] to continue"
    sleep 1

    __kill_daemons
}

function __init_gnupg() {
    export GNUPGHOME="$(pwd)/gnupg.tmpfs"
    __cmd mkdir -p "${GNUPGHOME}"
    __cmd mount -t tmpfs tmpfs "${GNUPGHOME}"
    __cmd chmod 700 "${GNUPGHOME}"

    __cmd curl -s -o "${GNUPGHOME}/gpg.conf" https://raw.githubusercontent.com/drduh/config/master/gpg.conf
}

function __init_backup() {
    if [ "$JANUS_NOBACKUP" = true ] ; then
        return
    fi

    if [ ! -d "backup.tmpfs" ] ; then
        __cmd mkdir "backup.tmpfs"
        __cmd mount -t tmpfs tmpfs backup.tmpfs
    fi
}

function __init_export() {
    if [ "$JANUS_NOEXPORT" = true ] ; then
        return
    fi

    if [ ! -d "export.tmpfs" ] ; then
        __cmd mkdir "export.tmpfs"
        __cmd mount -t tmpfs tmpfs export.tmpfs
    fi
}

function __init_piv() {
    if [ ! -d "piv.tmpfs" ] ; then
        __cmd mkdir "piv.tmpfs"
        __cmd mount -t tmpfs tmpfs piv.tmpfs
    fi
}

function __init_efi() {
    if [ ! -d "efi.tmpfs" ] ; then
        __cmd mkdir "efi.tmpfs"
        __cmd mount -t tmpfs tmpfs efi.tmpfs
    fi
}

function __gpg_card_guidance() {
    echo "Run the following commands when presented with the GPG prompt:"
    
    while (($#)); do
        echo -e "\t$1"
        shift
    done

    read -rp "Press [ENTER] to proceed..."
    gpg --card-edit
}

function __gpg_key_guidance() {
    local _key="$1"

    echo "Run the following commands when presented with the GPG prompt:"

    shift
    while (($#)); do
        echo -e "\t$1"
        shift
    done

    read -rp "Press [ENTER] to proceed..."
    gpg --edit-key "$_key"
}

function __setup_gnupg_external() {
    gpg --batch \
        --passphrase-fd 0 \
        --quick-generate-key \
        "$JANUS_GPG_IDENTITY" \
        "$JANUS_GPG_KEYTYPE" \
        cert never <<< "$JANUS_GPG_PASSPHRASE"

    JANUS_GPG_KEY_ID=$(gpg -k --with-colons "$JANUS_GPG_IDENTITY" | awk -F: '/^pub:/ { print $5; exit }')
    JANUS_GPG_KEY_FP=$(gpg -k --with-colons "$JANUS_GPG_IDENTITY" | awk -F: '/^fpr:/ { print $10; exit }')

    if [ -n "$JANUS_GPG_ADDITIONAL_IDENTITIES" ] ; then
        # JANUS_GPG_ADDITIONAL_IDENTITIES is a comma-separated list of identities
        echo "$JANUS_GPG_ADDITIONAL_IDENTITIES" | tr ',' '\n' | while read -r _identity; do
            gpg --quick-add-uid \
                "$JANUS_GPG_KEY_FP" \
                "$_identity"
        done
    fi

    __gpg_key_guidance "$JANUS_GPG_KEY_ID" \
        "uid *" \
        "trust" \
        "5" \
        "y" \
        "save"

    set -- sign encrypt auth

    while (($#)); do
        gpg --batch \
            --pinentry-mode=loopback \
            --passphrase-fd 0 \
            --quick-add-key \
            "$JANUS_GPG_KEY_FP" \
            "$JANUS_GPG_KEYTYPE" \
            "$1" \
            "$JANUS_GPG_EXPIRATION" <<< "$JANUS_GPG_PASSPHRASE"
        shift
    done
}

function __setup_gnupg() {
    if [ "$JANUS_NOBACKUP__DISABLED" = true ] ; then
        __setup_gnupg_onkey
    else
        __setup_gnupg_external
    fi
}

function __piv_csr_config() {
    local _email
    local -a _lines
    local _slot="$1"

    _email="$(echo "$JANUS_GPG_IDENTITY" | cut -d'<' -f2 | cut -d'>' -f1)"
    _lines=(
        "[req]"
        "distinguished_name = req_distinguished_name"
        "req_extensions = req_ext"
        "prompt = no"
        ""
        "[req_distinguished_name]"
        "countryName = US"
        "stateOrProvinceName = Ohio"
        "localityName = Akron"
        "organizationName = ${JANUS_ORG}"
        "organizationalUnitName = Operators"
    )

    case "$_slot" in
        9a)
            _lines+=("commonName = ${JANUS_USER_NAME}") ;;
        9c)
            _lines+=("commonName = ${JANUS_USER_NAME} (Signature)") ;;
        9d)
            _lines+=("commonName = ${JANUS_USER_NAME} (Encryption)") ;;
        9e)
            _lines+=("commonName = ${JANUS_USER_NAME} (Card Authentication)") ;;
    esac

    _lines+=(
        "emailAddress = ${_email}"
        ""
        "[req_ext]"
        "basicConstraints = CA:false"
    )

    case "$_slot" in
        9a)
            _lines+=(
                "subjectAltName = @alt_names"
                "keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment"
                "extendedKeyUsage = clientAuth,  1.3.6.1.4.1.311.20.2.2"
                ""
                "[alt_names]"
                "otherName = 1.3.6.1.4.1.311.20.2.3;UTF8:${_email}"
                "email = ${_email}"
            ) ;;
        9c)
            _lines+=(
                "subjectAltName = @alt_names"
                "keyUsage = critical, nonRepudiation, digitalSignature"
                "extendedKeyUsage = emailProtection, codeSigning"
                ""
                "[alt_names]"
                "email = ${_email}"
            ) ;;
        9d)
            _lines+=(
                "subjectAltName = @alt_names"
                "keyUsage = critical, keyEncipherment, dataEncipherment, keyAgreement"
                "extendedKeyUsage = emailProtection"
                ""
                "[alt_names]"
                "email = ${_email}"
            ) ;;
        9e)
            _lines+=(
                "keyUsage = critical, digitalSignature, keyEncipherment"
                "extendedKeyUsage = clientAuth, 2.16.840.1.101.3.6.7"
            ) ;;
    esac

    printf "%s\n" "${_lines[@]}"
}

function __setup_piv_external_ca() {
    local _passphrase _email

    _email="$(echo "$JANUS_GPG_IDENTITY" | cut -d'<' -f2 | cut -d'>' -f1)"

    for _slot in 9a 9c 9d 9e; do
        _passphrase="JANUS_PIV_PASSPHRASE_${_slot^^}"

        __piv_csr_config "${_slot}" > piv.tmpfs/piv.slot-${_slot}.cnf

        openssl req -config piv.tmpfs/piv.slot-${_slot}.cnf \
            -new -sha256 -key piv.tmpfs/piv.slot-${_slot}.priv.pem \
            -out piv.tmpfs/piv.slot-${_slot}.csr.pem \
            -passin pass:"${!_passphrase}" \
            -batch
    done

    pushd "${JANUS_MOUNTPOINT}/enacted/ca" >&/dev/null

    for _slot in 9a 9c 9d 9e; do
        openssl ca -config intermediateCA.cnf \
            -extensions usr_cert_${_slot} \
            -days 730 -notext -md sha256 \
            -in /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/piv.tmpfs/piv.slot-${_slot}.csr.pem \
            -out /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/piv.tmpfs/piv.slot-${_slot}.crt.pem \
            -passin pass:"$(cat intermediateCA.passphrase.txt)" \
            -batch
    done

    popd >&/dev/null
}

function __setup_piv_external() {
    local _passphrase
    for _slot in 9a 9c 9d 9e; do
        _passphrase="JANUS_PIV_PASSPHRASE_${_slot^^}"
        openssl genrsa -aes256 -out piv.tmpfs/piv.slot-${_slot}.priv.pem -passout pass:"${!_passphrase}" 2048
        openssl rsa -in piv.tmpfs/piv.slot-${_slot}.priv.pem -passin pass:"${!_passphrase}" -pubout -out piv.tmpfs/piv.slot-${_slot}.pub.pem
    done

    __setup_piv_external_ca
}

function __setup_piv() {
    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping PIV external setup"
        return
    fi

    if [ "$JANUS_NOBACKUP__DISABLED" = true ] ; then
        __setup_piv_onkey
    else
        __setup_piv_external
    fi
}

function __setup_efi_external_ca() {
    local _email _passphrase _file
    _email="$(echo "$JANUS_GPG_IDENTITY" | cut -d'<' -f2 | cut -d'>' -f1)"

    pushd "${JANUS_MOUNTPOINT}/enacted/efi-kek" >&/dev/null

    openssl genrsa -aes256 \
        -out /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-user.priv.pem \
        -passout pass:"${JANUS_EFI_PASSPHRASE_USER}" 2048

    openssl rsa \
        -in /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-user.priv.pem \
        -passin pass:"$JANUS_EFI_PASSPHRASE_USER" \
        -pubout \
        -out /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-user.pub.pem

    openssl req -config kekCA.cnf \
        -new -sha256 -key /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-user.priv.pem \
        -out /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-user.csr.pem \
        -passin pass:"${JANUS_EFI_PASSPHRASE_USER}" \
        -subj "/C=US/ST=Ohio/L=Akron/O=${JANUS_ORG}/OU=EFI Secure Boot/CN=${JANUS_HOSTNAME^^} User Key" \
        -batch

    openssl ca -config kekCA.cnf \
        -extensions efi_db \
        -days 730 -notext -md sha256 \
        -in /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-user.csr.pem \
        -out /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-user.crt.pem \
        -passin pass:"$(cat kekCA.passphrase.txt)" \
        -batch

    set -- ${JANUS_MACHINES:+ ${JANUS_MACHINES//,/ }}

    while (($#)) ; do
        _passphrase=$(( 4 - $# ))
        _passphrase="$(echo -e "$JANUS_EFI_PASSPHRASE_MACHINES" | cut -f $_passphrase)"

        openssl genrsa -aes256 \
            -out /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-machine-$1.priv.pem \
            -passout pass:"${_passphrase}" 2048

        openssl rsa \
            -in /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-machine-$1.priv.pem \
            -passin pass:"${_passphrase}" \
            -pubout \
            -out /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-machine-$1.pub.pem

        openssl req -config kekCA.cnf \
            -new -sha256 -key /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-machine-$1.priv.pem \
            -out /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-machine-$1.csr.pem \
            -passin pass:"${_passphrase}" \
            -subj "/C=US/ST=Ohio/L=Akron/O=${JANUS_ORG}/OU=EFI Secure Boot/CN=${JANUS_HOSTNAME^^} ${1^} Machine Key" \
            -batch

        openssl ca -config kekCA.cnf \
            -extensions efi_db \
            -days 730 -notext -md sha256 \
            -in /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-machine-$1.csr.pem \
            -out /mnt/bootstrap/@bootstrap/@f516z33/@yubikey/efi.tmpfs/efi.db-machine-$1.crt.pem \
            -passin pass:"$(cat kekCA.passphrase.txt)" \
            -batch

        shift
    done

    popd >&/dev/null

    cd efi.tmpfs

    # EFI certs
    cp "${JANUS_MOUNTPOINT}/enacted/efi-db/db/efi.guid.txt" efi.guid.txt

    for _file in *.crt.pem; do
        cert-to-efi-sig-list -g "$(< efi.guid.txt)" "$_file" "${_file%.crt.pem}.esl"
    done

    cp "${JANUS_MOUNTPOINT}/enacted/efi-db/db/efi.db-org.esl" efi.db-org.esl
    cat efi.db-org.esl efi.db-user.esl efi.db-machine-*.esl > efi.db.esl

    mkfifo privkey.fifo
    openssl rsa \
        -in "${JANUS_MOUNTPOINT}/enacted/efi-kek/efi.kek-org.priv.pem" \
        -passin pass:"$(cat "${JANUS_MOUNTPOINT}/enacted/efi-kek/kekCA.passphrase.txt")" \
        -out privkey.fifo &

    sign-efi-sig-list \
        -k privkey.fifo \
        -c "${JANUS_MOUNTPOINT}/enacted/efi-kek/efi.kek-org.crt.pem" \
        db efi.db.esl efi.db.auth &
    wait
    rm privkey.fifo

    cp "${JANUS_MOUNTPOINT}/enacted/efi-db/import/efi.pk-org.auth" efi.pk.auth
    cp "${JANUS_MOUNTPOINT}/enacted/efi-db/import/efi.kek-org.auth" efi.kek.auth

    cd ..   
}

function __setup_efi_external() {
    local _passphrase _stem
    if [ ! "$JANUS_EFI_PASSPHRASE_MACHINES" = "_random_" ] ; then
        echo "EFI passphrase for machines must be random" >&2
        exit 1
    fi

	set -- ${JANUS_MACHINES:+ ${JANUS_MACHINES//,/ }}

    JANUS_EFI_PASSPHRASE_MACHINES="$(__bip39)"
    shift
    while (($#)); do
        JANUS_EFI_PASSPHRASE_MACHINES="$JANUS_EFI_PASSPHRASE_MACHINES"$'\t'"$(__bip39)"
        shift
    done

    # Generate certs depending on JANUS_CA
    if [ "$JANUS_CA__DISABLED" = false ] ; then
        __setup_efi_external_selfsigned
    else
        __setup_efi_external_ca
    fi
}

function __setup_efi() {
    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping PIV external setup"
        return
    fi

    if [ "$JANUS_NOBACKUP__DISABLED" = true ] ; then
        __setup_efi_onkey
    else
        __setup_efi_external
    fi
}

function __export_efi() {
    if [ "$JANUS_NOEXPORT" = true ] ; then
        return
    fi

    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping EFI export"
        return
    fi

    mkdir -p export.tmpfs/efi/import

    cp efi.tmpfs/efi.pk.auth export.tmpfs/efi/import/pk.auth
    cp efi.tmpfs/efi.kek.auth export.tmpfs/efi/import/kek.auth
    cp efi.tmpfs/efi.db.auth export.tmpfs/efi/import/db.auth
    
    mkdir -p export.tmpfs/efi/certs

    cp efi.tmpfs/efi.db-user.crt.pem export.tmpfs/efi/certs/user.crt.pem

    set -- ${JANUS_MACHINES:+ ${JANUS_MACHINES//,/ }}

    while (($#)); do
        cp efi.tmpfs/efi.db-machine-$1.crt.pem export.tmpfs/efi/certs/machine-$1.crt.pem
        shift
    done
}

function __backup_efi() {
    if [ "$JANUS_NOBACKUP" = true ] ; then
        return
    fi

    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping EFI backup"
        return
    fi

    mkdir -p backup.tmpfs/efi
    cp efi.tmpfs/*.esl backup.tmpfs/efi
    cp efi.tmpfs/*.auth backup.tmpfs/efi
    cp efi.tmpfs/*.crt.pem backup.tmpfs/efi
    cp efi.tmpfs/*.priv.pem backup.tmpfs/efi
    cp efi.tmpfs/*.pub.pem backup.tmpfs/efi
    cp efi.tmpfs/*.txt backup.tmpfs/efi
}

function __export_piv() {
    if [ "$JANUS_NOEXPORT" = true ] ; then
        return
    fi

    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping PIV export"
        return
    fi

    mkdir -p export.tmpfs/piv

    cp piv.tmpfs/piv.slot-9a.crt.pem export.tmpfs/piv/slot-9a.crt.pem
    cp piv.tmpfs/piv.slot-9c.crt.pem export.tmpfs/piv/slot-9c.crt.pem
    cp piv.tmpfs/piv.slot-9d.crt.pem export.tmpfs/piv/slot-9d.crt.pem
    cp piv.tmpfs/piv.slot-9e.crt.pem export.tmpfs/piv/slot-9e.crt.pem
}

function __backup_piv() {
    if [ "$JANUS_NOBACKUP" = true ] ; then
        return
    fi

    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping PIV backup"
        return
    fi

    mkdir -p backup.tmpfs/piv
    cp piv.tmpfs/*.crt.pem backup.tmpfs/piv
    cp piv.tmpfs/*.priv.pem backup.tmpfs/piv
    cp piv.tmpfs/*.pub.pem backup.tmpfs/piv
}

function __export_gnupg() {
    if [ "$JANUS_NOEXPORT" = true ] ; then
        return
    fi

    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping GPG export"
        return
    fi

    mkdir -p export.tmpfs/gpg

    gpg \
        --armor \
        --output export.tmpfs/gpg/certify.pub.asc \
        --export "$JANUS_GPG_KEY_ID"
    
    printf "Key ID: %40s\nKey FP: %40s\n\n" "$JANUS_GPG_KEY_ID" "$JANUS_GPG_KEY_FP" > export.tmpfs/gpg/key-info.txt
}

function __backup_gnupg() {
    if [ "$JANUS_NOBACKUP" = true ] ; then
        return
    fi

    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping GPG backup"
        return
    fi

    mkdir -p backup.tmpfs/gpg

    printf "Key ID: %40s\nKey FP: %40s\n\n" "$JANUS_GPG_KEY_ID" "$JANUS_GPG_KEY_FP" > backup.tmpfs/gpg/key-info.txt

    gpg \
        --armor \
        --output backup.tmpfs/gpg/certify.pub.asc \
        --export "$JANUS_GPG_KEY_ID"

    gpg \
        --batch \
        --armor \
        --output backup.tmpfs/gpg/certify.key.asc \
        --pinentry-mode=loopback \
        --passphrase-fd 0 \
        --export-secret-keys "$JANUS_GPG_KEY_ID" \
        <<< "$JANUS_GPG_PASSPHRASE"

    gpg \
        --batch \
        --armor \
        --output backup.tmpfs/gpg/subkeys.key.asc \
        --pinentry-mode=loopback \
        --passphrase-fd 0 \
        --export-secret-subkeys "$JANUS_GPG_KEY_ID" \
        <<< "$JANUS_GPG_PASSPHRASE"

    echo "Choose 0"
    gpg \
        --armor \
        --output backup.tmpfs/gpg/revoke.asc \
        --gen-revoke "$JANUS_GPG_KEY_ID"

    echo "Choose 1"
    gpg \
        --armor \
        --output backup.tmpfs/gpg/revoke.compromised.asc \
        --gen-revoke "$JANUS_GPG_KEY_ID"

    echo "Choose 2"
    gpg \
        --armor \
        --output backup.tmpfs/gpg/revoke.superseded.asc \
        --gen-revoke "$JANUS_GPG_KEY_ID"

    echo "Choose 3"
    gpg \
        --armor \
        --output backup.tmpfs/gpg/revoke.unused.asc \
        --gen-revoke "$JANUS_GPG_KEY_ID"
}

function __transfer_piv() {
    local _pin_policy _touch_policy _passphrase

    __kill_daemons
    
    read -p "Insert YubiKey and press [ENTER] to continue"
    sleep 2

    for _slot in 9a 9c 9d 9e; do
        _passphrase="JANUS_PIV_PASSPHRASE_${_slot^^}"

        if [ "$JANUS_TOUCH" = true ]; then
            _touch_policy="ALWAYS"
        else
            _touch_policy="DEFAULT"
        fi

        if [ "${_slot}" = "9e" ]; then
            _pin_policy="NEVER"
            _touch_policy="NEVER"
        else
            _pin_policy="DEFAULT"
        fi

        ykman piv keys import \
            --management-key "$JANUS_PIV_MGM" \
            --pin "$JANUS_PIV_PIN" \
            --password "${!_passphrase}" \
            --touch-policy "$_touch_policy" \
            --pin-policy "$_pin_policy" \
            "${_slot}" "piv.tmpfs/piv.slot-${_slot}.priv.pem"

        ykman piv certificates import \
            --management-key "$JANUS_PIV_MGM" \
            --pin "$JANUS_PIV_PIN" \
            --password "${!_passphrase}" \
            --verify \
            "${_slot}" "piv.tmpfs/piv.slot-${_slot}.crt.pem"
    done

    read -p "Remove YubiKey and press [ENTER] to continue"
    sleep 1

    __kill_daemons
}

function __transfer_efi() {
    __kill_daemons
    read -p "Insert YubiKey and press [ENTER] to continue"
    sleep 2

    local _pin_policy _touch_policy _passphrase
    local -a _map_idx=95
    local -a _map=(
        "95" "db-user" "${JANUS_EFI_PASSPHRASE_USER}"
    )

    set -- ${JANUS_MACHINES:+ ${JANUS_MACHINES//,/ }}

    while (($#)); do
        _passphrase=$(( 4 - $# ))
        _passphrase="$(echo -e "$JANUS_EFI_PASSPHRASE_MACHINES" | cut -f $_passphrase)"

        _map_idx=$(( _map_idx - 1 ))
        _map+=("${_map_idx}" "db-machine-$1" "${_passphrase}")
        shift
    done

    set -- "${_map[@]}"

    while (($#)); do
        if [ "$JANUS_TOUCH" = true ]; then
            _touch_policy="ALWAYS"
            _pin_policy="ALWAYS"
        else
            _touch_policy="NEVER"
            _pin_policy="ONCE"
        fi

        ykman piv keys import \
            --management-key "$JANUS_PIV_MGM" \
            --pin "$JANUS_PIV_PIN" \
            --password "$3" \
            --touch-policy "$_touch_policy" \
            --pin-policy "$_pin_policy" \
            "$1" "efi.tmpfs/efi.$2.priv.pem"

        ykman piv certificates import \
            --management-key "$JANUS_PIV_MGM" \
            --pin "$JANUS_PIV_PIN" \
            --password "$3" \
            --verify \
            "$1" "efi.tmpfs/efi.$2.crt.pem"

        shift 3
    done

    read -p "Remove YubiKey and press [ENTER] to continue"
    sleep 1

    __kill_daemons
}

function __transfer_gnupg() {
    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping GPG transfer"
        return
    fi

    __kill_daemons
    read -p "Insert YubiKey and press [ENTER] to continue"
    sleep 2

    __gpg_key_guidance "$JANUS_GPG_KEY_ID" \
        "key 1" \
        "keytocard" \
        "1" \
        "$JANUS_GPG_PASSPHRASE" \
        "$JANUS_GPG_ADMIN_PIN" \
        "key 1" \
        "key 2" \
        "keytocard" \
        "2" \
        "$JANUS_GPG_PASSPHRASE" \
        "$JANUS_GPG_ADMIN_PIN" \
        "key 2" \
        "key 3" \
        "keytocard" \
        "3" \
        "$JANUS_GPG_PASSPHRASE" \
        "$JANUS_GPG_ADMIN_PIN" \
        "key 3" \
        "save"

    read -p "Remove YubiKey and press [ENTER] to continue"
    sleep 1

    __kill_daemons
}

function __setup_luks() {
    local _machine
    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping luks setup"
        return
    fi

    for _machine in ${JANUS_MACHINES//,/ } ; do
        dd if=/dev/urandom bs=1024 count=4 \
            | gpg --cipher-algo AES256 \
                --passphrase "$JANUS_GPG_PASSPHRASE" \
                --batch \
                --encrypt \
                --recipient "$JANUS_GPG_KEY_ID" \
            > luks.tmpfs/${JANUS_HOSTNAME}.${_machine}.keyfile.gpg
    done
}

function __init_luks() {
    if [ "$JANUS_NOBACKUP" = true ] ; then
        return
    fi

    if [ ! -d "luks.tmpfs" ] ; then
        __cmd mkdir "luks.tmpfs"
        __cmd mount -t tmpfs tmpfs luks.tmpfs
    fi
}

function __export_luks() {
    if [ "$JANUS_NOEXPORT" = true ] ; then
        return
    fi

    if [ "$JANUS_DRYRUN" = true ]; then
        echo "Dry run: skipping LUKS export"
        return
    fi

    cp -a luks.tmpfs export.tmpfs/luks
}

function __finalize_luks() {
    __export_luks
}

function __finalize_efi() {
    __export_efi
    __backup_efi
}

function __finalize_piv() {
    __export_piv
    __backup_piv
}

function __finalize_ca() {
    __export_ca
    __backup_ca
}

function __finalize_gnupg() {
    __export_gnupg
    __backup_gnupg
}

function __finalize_backup() {
    local _passphrase
    printf '%s' "$JANUS_GPG_PASSPHRASE" > backup.tmpfs/gpg/passphrase.txt

    mkdir -p backup.tmpfs/yubikey/gpg
    printf 'GPG Admin Pin: %12s\nGPG User Pin: %13s\n' \
        "$JANUS_GPG_ADMIN_PIN" \
        "$JANUS_GPG_USER_PIN" \
        > backup.tmpfs/yubikey/gpg/pin-info.txt


    mkdir -p backup.tmpfs/yubikey/piv
    printf '%s' "$JANUS_PIV_MGM" > backup.tmpfs/yubikey/piv/mgm-key.txt
    printf 'PIV PUK: %12s\nPIV Pin: %12s\n' \
        "$JANUS_PIV_PUK" \
        "$JANUS_PIV_PIN" \
        > backup.tmpfs/yubikey/piv/pin-info.txt


    printf '%s' "$JANUS_PIV_PASSPHRASE_9A" > backup.tmpfs/piv/piv.slot-9a.passphrase.txt
    printf '%s' "$JANUS_PIV_PASSPHRASE_9C" > backup.tmpfs/piv/piv.slot-9c.passphrase.txt
    printf '%s' "$JANUS_PIV_PASSPHRASE_9D" > backup.tmpfs/piv/piv.slot-9d.passphrase.txt
    printf '%s' "$JANUS_PIV_PASSPHRASE_9E" > backup.tmpfs/piv/piv.slot-9e.passphrase.txt

    printf '%s' "$JANUS_EFI_PASSPHRASE_USER" > backup.tmpfs/efi/efi.db-user.passphrase.txt

    set -- ${JANUS_MACHINES:+ ${JANUS_MACHINES//,/ }}

    while (($#)); do
        _passphrase=$(( 4 - $# ))
        _passphrase="$(echo -e "$JANUS_EFI_PASSPHRASE_MACHINES" | cut -f $_passphrase)"

        printf '%s' \
            "$_passphrase" \
            > backup.tmpfs/efi/efi.db-machine-$1.passphrase.txt
        shift
    done

    mkdir -p backup.tmpfs/efi/{db,import}

    mv backup.tmpfs/efi/*.auth backup.tmpfs/efi/import

    mv backup.tmpfs/efi/efi.db* backup.tmpfs/efi/db
    mv backup.tmpfs/efi/efi.*.txt backup.tmpfs/efi/db

    cp -a /mnt/bootstrap/@bootstrap/repart/yubikey backup.tmpfs/repart.d
    sed -i "s|__PWD__|$(pwd)|g" backup.tmpfs/repart.d/*.conf
    mkdir -p backup.tmpfs/repart.target

    cp backup.tmpfs/repart.d/10-gnupg.conf backup.tmpfs/repart.target

    mkfifo backup.tmpfs/repart.keyfifo
    gpg --cipher-algo AES256 \
        --passphrase "$JANUS_GPG_PASSPHRASE" \
        --batch \
        --pinentry-mode=loopback \
        --passphrase-fd 0 \
        --symmetric \
        --output - \
        <(dd if=/dev/urandom bs=1024 count=4) \
        <<< "$JANUS_GPG_PASSPHRASE" \
        > backup.tmpfs/gpg-${JANUS_GPG_KEY_ID}.keyfile.gpg

    gpg --passphrase "$JANUS_GPG_PASSPHRASE" \
        --batch \
        --decrypt backup.tmpfs/gpg-${JANUS_GPG_KEY_ID}.keyfile.gpg \
        > backup.tmpfs/repart.keyfifo &

    systemd-repart \
        --empty=create \
        --definitions=backup.tmpfs/repart.target \
        --size=auto \
        --key-file=backup.tmpfs/repart.keyfifo \
        gpg-${JANUS_GPG_KEY_ID}.raw

    rm backup.tmpfs/repart.keyfifo backup.tmpfs/repart.target/*


    dd if=/dev/urandom bs=1024 count=4 \
        | gpg --cipher-algo AES256 \
            --passphrase "$JANUS_GPG_PASSPHRASE" \
            --batch \
            --encrypt \
            --recipient "$JANUS_GPG_KEY_ID" \
        > backup.tmpfs/piv-${JANUS_USERNAME}.keyfile.gpg
    dd if=/dev/urandom bs=1024 count=4 \
        | gpg --cipher-algo AES256 \
            --passphrase "$JANUS_GPG_PASSPHRASE" \
            --batch \
            --encrypt \
            --recipient "$JANUS_GPG_KEY_ID" \
        > backup.tmpfs/efi-db-${JANUS_ORG// /_}.keyfile.gpg
    dd if=/dev/urandom bs=1024 count=4 \
        | gpg --cipher-algo AES256 \
            --passphrase "$JANUS_GPG_PASSPHRASE" \
            --batch \
            --encrypt \
            --recipient "$JANUS_GPG_KEY_ID" \
        > backup.tmpfs/yubikey-${JANUS_USERNAME}.keyfile.gpg

    mkfifo backup.tmpfs/repart.keyfifo
    gpg --batch \
        --pinentry-mode=loopback \
        --passphrase-fd 0 \
        --output - \
        --decrypt backup.tmpfs/piv-${JANUS_USERNAME}.keyfile.gpg \
        <<< "$JANUS_GPG_PASSPHRASE" \
        > backup.tmpfs/repart.keyfifo &

    cp backup.tmpfs/repart.d/20-piv.conf backup.tmpfs/repart.target
    systemd-repart \
        --empty=create \
        --definitions=backup.tmpfs/repart.target \
        --size=auto \
        --key-file=backup.tmpfs/repart.keyfifo \
        piv-${JANUS_USERNAME}.raw

    rm backup.tmpfs/repart.keyfifo backup.tmpfs/repart.target/*

    mkfifo backup.tmpfs/repart.keyfifo
    gpg --batch \
        --pinentry-mode=loopback \
        --passphrase-fd 0 \
        --output - \
        --decrypt backup.tmpfs/efi-db-${JANUS_ORG// /_}.keyfile.gpg \
        <<< "$JANUS_GPG_PASSPHRASE" \
        > backup.tmpfs/repart.keyfifo &

    cp backup.tmpfs/repart.d/70-efi-db.conf backup.tmpfs/repart.target
    systemd-repart \
        --empty=create \
        --definitions=backup.tmpfs/repart.target \
        --size=auto \
        --key-file=backup.tmpfs/repart.keyfifo \
        efi-db-${JANUS_ORG// /_}.raw

    rm backup.tmpfs/repart.keyfifo backup.tmpfs/repart.target/*

    mkfifo backup.tmpfs/repart.keyfifo
    gpg --batch \
        --pinentry-mode=loopback \
        --passphrase-fd 0 \
        --output - \
        --decrypt backup.tmpfs/yubikey-${JANUS_USERNAME}.keyfile.gpg \
        <<< "$JANUS_GPG_PASSPHRASE" \
        > backup.tmpfs/repart.keyfifo &

    cp backup.tmpfs/repart.d/80-yubikey.conf backup.tmpfs/repart.target
    systemd-repart \
        --empty=create \
        --definitions=backup.tmpfs/repart.target \
        --size=auto \
        --key-file=backup.tmpfs/repart.keyfifo \
        yubikey-${JANUS_USERNAME}.raw

    rm backup.tmpfs/repart.keyfifo backup.tmpfs/repart.target/*
    mv backup.tmpfs/*.keyfile.gpg ./
}

function __finalize_export() {
    mv export.tmpfs/* ./
}

function __display_passphrases() {
    # The user should only need the GPG passphrase to get to the rest
    # Be sure to warn them to record it securely, and that it will not
    # be displayed again or recoverable if lost.
    echo
    echo -e "\033[1m=============================================\033[0m"
    echo -e "\033[1m===           GPG PASSCODE               ===\033[0m"
    echo -e "\033[1m=============================================\033[0m"
    echo
    echo "Record this securely, It will not be shown again!"
    echo
    echo -e "GPG Passphrase:\033[31m $JANUS_GPG_PASSPHRASE \033[0m\n"
    echo
    qrencode -t ANSIUTF8 -l H -o - <<< "$JANUS_GPG_PASSPHRASE"
    echo
    echo -e "GPG Passphrase:\033[31m $JANUS_GPG_PASSPHRASE \033[0m\n"
    echo
    echo "Record this securely, It will not be shown again!"
    echo
    echo -e "\033[1m=============================================\033[0m"
}

function __finalize_yubikey() {
    __transfer_piv
    __transfer_efi
    __transfer_gnupg
    __display_passphrases
}

##
## Main
##

function __main() {
    if [ -d "/mnt/bootstrap/@bootstrap/@${JANUS_HOSTNAME}/@yubikey" ] ; then
        return
    fi

    __cmd btrfs subvol create "/mnt/bootstrap/@bootstrap/@${JANUS_HOSTNAME}/@yubikey"
    cd "/mnt/bootstrap/@bootstrap/@${JANUS_HOSTNAME}/@yubikey"


    __init_passphrases

    __init_gnupg
    __init_backup
    __init_export
    __init_piv
    __init_efi
    __init_luks

    __setup_gnupg
    __setup_piv
    __setup_efi
    __setup_luks

    __finalize_gnupg
    __finalize_piv
    __finalize_efi
    __finalize_luks

    __finalize_backup
    __finalize_export

    __reset_yubikey
    __init_yubikey
    __finalize_yubikey

    umount -R /mnt/bootstrap/@bootstrap/@${JANUS_HOSTNAME}/@yubikey/*.tmpfs || true
    rm -rf /mnt/bootstrap/@bootstrap/@${JANUS_HOSTNAME}/@yubikey/*.tmpfs
}

##
## Entrypoint
##

JANUS_DEBUG=false
JANUS_VERBOSE=false
JANUS_FORCE=false
JANUS_DRYRUN=false
JANUS_NOEXPORT=false
JANUS_NOBACKUP=false
JANUS_INSECURE=false
JANUS_HOSTNAME="$(hostname -s)"
JANUS_MACHINES="main,test,dbug"
JANUS_HELP=false
JANUS_GPG_IDENTITY="${JANUS_HOSTNAME} Administrator <root@${JANUS_HOSTNAME}>"
JANUS_GPG_KEYTYPE=rsa4096
JANUS_GPG_EXPIRATION=2y
JANUS_GPG_ADMIN_PIN=87654321
JANUS_GPG_USER_PIN=654321
JANUS_PIV_PUK=87654321
JANUS_PIV_PIN=654321
JANUS_PIV_MGM=8070605040302010807060504030201080706050403020108070605040302010
JANUS_ORG="Enacted Services"
JANUS_DN="enacted.cloud"
JANUS_USER_NAME="Jaremy Hatler"
JANUS_USERNAME="jhatler"
JANUS_GPG_PASSPHRASE=_random_
JANUS_CA=false
JANUS_CA_ROOT_PASSPHRASE=_random_
JANUS_CA_INTERMEDIATE_PASSPHRASE=_random_
JANUS_PIV_PASSPHRASE_9A=_random_
JANUS_PIV_PASSPHRASE_9C=_random_
JANUS_PIV_PASSPHRASE_9D=_random_
JANUS_PIV_PASSPHRASE_9E=_random_
JANUS_EFI_PASSPHRASE_PK=_random_
JANUS_EFI_PASSPHRASE_KEK=_random_
JANUS_EFI_PASSPHRASE_USER=_random_
JANUS_EFI_PASSPHRASE_MACHINES=_random_
JANUS_GPG_USE_OTP=false
JANUS_GPG_PASSPHRASE=_random_
JANUS_LUKS_PASSPHRASE=_random_
JANUS_TOUCH=false
JANUS_EFI=false
JANUS_MOUNTPOINT="/mnt/bootstrap/@bootstrap/@${JANUS_HOSTNAME}/@yubikey.tmpfs"

while getopts ":hH:M:XBIG:a:A:p:P:K:U:u:CR:r:O:D:TtEe:S:s:fnvd" OPTVAL; do
	case $OPTVAL in
		H) # Specify base hostname to create
			JANUS_HOSTNAME="$OPTARG"
			;;
		M) # Limit activities to machine variants (comma separated, ? for list)
			JANUS_MACHINES="$OPTARG"
			;;
        X) # Do not export public materials to the local filesystem
            JANUS_NOEXPORT=true
            ;;
        B) # Do not backup private materials (encrypted) to the local filesystem
            JANUS_NOBACKUP=true
            ;;
        I) # Insecure mode (used for testing)
            JANUS_INSECURE=true
            ;;
        C) # Create and use certificate authority
            JANUS_CA=true
            ;;
        G) # GPG Identity 
            JANUS_GPG_IDENTITY="$OPTARG"
            ;;
        A) # GPG Admin Pin
            JANUS_GPG_ADMIN_PIN="$OPTARG"
            ;;
        a) # PIV PUK
            JANUS_PIV_PUK="$OPTARG"
            ;;
        P) # GPG User Pin
            JANUS_GPG_USER_PIN="$OPTARG"
            ;;
        p) # PIV PIN
            JANUS_PIV_PIN="$OPTARG"
            ;;
        K) # PIV Management Key
            JANUS_PIV_MGM="$OPTARG"
            ;;
		f) # Force the operation
			JANUS_FORCE=true
			;;
        U) # User's Full Name
            JANUS_USER_NAME="$OPTARG"
            ;;
        u) # User's GitHub Username
            JANUS_USERNAME="$OPTARG"
            ;;
        R) # GPG Passphrase (default: _random_)
            JANUS_GPG_PASSPHRASE="$OPTARG"
            ;;
        r) # LUKS Passphrase (default: _random_)
            JANUS_LUKS_PASSPHRASE="$OPTARG"
            ;;
        S) # CA Root Passphrase (default: _random_)
            JANUS_CA_ROOT_PASSPHRASE="$OPTARG"
            ;;
        s) # CA Intermediate Passphrase (default: _random_)
            JANUS_CA_INTERMEDIATE_PASSPHRASE="$OPTARG"
            ;;
        O) # Organization
            JANUS_ORG="$OPTARG"
            ;;
        D) # Domain Name
            JANUS_DN="$OPTARG"
            ;;
        t) # Use OTP for GPG
            JANUS_GPG_USE_OTP=true
            ;;
        T) # Enable touch requirements where possible
            JANUS_TOUCH=true
            ;;
        E) # Enable EFI key generation
            JANUS_EFI=true
            ;;
        e) # EFI factory source
            JANUS_EFI_FACTORY_SRC="$OPTARG"
            ;;
		n) # Dry run
			JANUS_DRYRUN=true
			;;
		v) # Verbose
			JANUS_VERBOSE=true
			;;
		d) # Debug
			set -x
			JANUS_DEBUG=true
			JANUS_VERBOSE=true
			;;
		h) # Display help and current settings
			JANUS_HELP=true
			;;
		*)
			__usage >&2
			exit 1
			;;
	esac
done

shift $((OPTIND-1))
unset OPTVAL OPTARG OPTERR OPTIND

if [[ $# -ne 0 ]]; then
	echo "Unrecognized arguments: " "$@" >&2
	__usage >&2
	exit 1
fi

if [ "$JANUS_INSECURE" = true ] && [ "$JANUS_FORCE" = false ]; then
    echo "Insecure mode requires force" >&2
    __usage >&2
    exit 1
fi

if [ "$JANUS_HELP" = true ]; then
	__usage >&2
	__settings >&2
	exit 0
fi

JANUS_GPG_KEY_FP=
JANUS_GPG_KEY_ID=

__main
