import {
    registerDynamicValueClass,
    InputField
} from './__mocks__/Shims'

import CryptoJS from 'crypto-js'

@registerDynamicValueClass
export default class DynamicValue {
    // TODO update static information with correct ones
    // Organisation
    static organisation = 'luckymarmot'
    static repository = 'Paw-AESDecryptDynamicValue'

    // Generator
    static identifier = 'com.luckymarmot.PawExtensions.AESDecryptDynamicValue'
    static title = 'AES Decrypt'

    static help = 'https://github.com/luckymarmot/Paw-AESDecryptDynamicValue'

    static inputs = [
        new InputField(
            'message',
            'Message',
            'SecureValue',
            {
                persisted: true,
                placeholder: 'the message to decrypt'
            }
        ),
        new InputField(
            'msgEnc',
            'Message Encoding',
            'Select',
            {
                persisted: true,
                choices: {
                    Hex: 'Hex',
                    Base64: 'Base 64',
                    Utf8: 'UTF 8 (default)',
                    Utf16: 'UTF 16',
                    Latin1: 'Latin1'
                },
                defaultValue: 'Utf8'
            }
        ),
        new InputField(
            'key',
            'Secret Key',
            'SecureValue',
            {
                persisted: true,
                placeholder: 'secret key'
            }
        ),
        new InputField(
            'iv',
            'Initialization Vector',
            'SecureValue',
            {
                persisted: true
            }
        ),
        new InputField(
            'ivEnc',
            'IV Encoding',
            'Select',
            {
                persisted: true,
                choices: {
                    Hex: 'Hex (default)',
                    Base64: 'Base 64',
                    Utf8: 'UTF 8',
                    Utf16: 'UTF 16',
                    Latin1: 'Latin1'
                },
                defaultValue: 'Hex'
            }
        ),
        new InputField(
            'mode',
            'Mode',
            'Select',
            {
                persisted: true,
                choices: {
                    CBC: 'Chipher Block Chain (default)',
                    CFB: 'Cipher Feedback',
                    CTR: 'Counter',
                    CTRGladman: 'Counter (Gladman)',
                    OFB: 'Output Feedback',
                    ECB: 'Electronic Codebook'
                },
                defaultValue: 'CBC'
            }
        ),
        new InputField(
            'pad',
            'Padding',
            'Select',
            {
                persisted: true,
                choices: {
                    Pkcs7: 'PKCS7 (default)',
                    Ansix923: 'ANSI X.923',
                    Iso10126: 'ISO 10126',
                    Iso97971: 'ISO/IEC 9797-1',
                    ZeroPadding: 'Zero Padding',
                    NoPadding: 'No Padding'
                },
                defaultValue: 'Pkcs7'
            }
        )
    ]

    // args: context
    evaluate() {
        if (
            !this.message ||
            !this.key ||
            !this.msgEnc ||
            !this.pad ||
            !this.mode
        ) {
            return null
        }

        const msgEnc = this.msgEnc || 'Utf8'
        const padding = this.pad || 'Pkcs7'
        const mode = this.mode || 'CBC'

        const options = {}
        let hasOptions = false
        if (this.iv) {
            let iv = this.iv
            if (this.ivEnc) {
                iv = CryptoJS.enc[this.ivEnc].parse(this.iv)
            }
            options.iv = iv
            hasOptions = true
        }

        if (this.pad && this.pad !== 'Pkcs7') {
            options.padding = CryptoJS.pad[padding]
            hasOptions = true
        }

        if (this.mode && this.mode !== 'CBC') {
            options.mode = CryptoJS.mode[mode]
            hasOptions = true
        }

        let decrypted = null
        if (hasOptions) {
            decrypted = CryptoJS.AES.decrypt(
                this.message,
                this.key,
                options
            )
        }
        else {
            decrypted = CryptoJS.AES.decrypt(
                this.message,
                this.key
            )
        }

        try {
            return decrypted.toString(CryptoJS.enc[msgEnc])
        }
        catch (e) {
            /* eslint-disable no-console */
            console.log('warn --- error in AES decrypt', e)
            /* eslint-enable no-console */
            return null
        }
    }
}
