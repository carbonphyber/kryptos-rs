extern crate clap;

use clap::{Arg, App};

use std::ascii::AsciiExt;

const ASCII_A: u8 = 'A' as u8;

// // Elonka ciphertext
// EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ
// YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD
// VFPJUDEEHZWETZYVGWHKKQETGFQJNCE
// GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG
// TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA
// QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR
// YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI
// HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE
// EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX
// FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF
// FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ
// ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE
// DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP
// DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG
// ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA
// CHTNREYULDSLLSLLNOHSNOSMRWXMNE
// TPRNGATIHNRARPESLNNELEBLPIIACAE
// WMTWNDITEENRAHCTENEUDRETNHAEOE
// TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR
// EIFTBRSPAMHHEWENATAMATEGYEERLB
// TEEFOASFIOTUETUAEOTOARMAEERTNRTI
// BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB
// AECTDDHILCEIHSITEGOEAOSDDRYDLORIT
// RKLMLEHAGTDHARDPNEOHMGFMFEUHE
// ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR
// UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO
// TWTQSJQSSEKZZWATJKLUDIAWINFBNYP
// VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR


// // CIA ciphertext
// EMUFP HZLRF AXYUS DJKZL DKRNS  HGNFI VJYQT QUXQB QVYUV LLTRE
// VJYQT MKYRD MFDVF PJUDE EHZWE  TZYVG WHKKQ ETGFQ JNCEG GWDKK
// TDQMC PFQZD QMMIA GPFXH ORGLT  IMVMZ JANQL VKQED AGDVF RPJUN
// GEUNA OZGZL ECGYU XUEEN JTBJL  BQCRT BJDFH RRYIZ ETKZE MVDUF
// KSJHK FWHKU WQLSZ FTIHH DDDUV    

// DWKBF UFPWN TOFIY CUQZE REEVL  DKFEZ MOQQJ LTTUG SYQPF EUNLA
// VIDXF LGGTE Z

// FKZBS FDQVG OGIPU FXHHD RKFFH  QNTGP UAECN UVPDJ MQCLQ UMUNE
// DFQEL ZZVRR GKFFV OEEXB DMVPN  FQXEZ LGRED NQFMP NZGLF LPMRJ
// QYALM GNUVP DXVKP DQUME BEEDM  DAFMJ GZNUP LGEWJ LLAET GENDY
// AHROH NLSRH EOCPT EOIBI DYSHN  AIACH TNREY ULDSL LSLLN OHSNO
// SMRWX MNETP RNGAT IHNRA RPESL  NNELE BLPII ACAEW MTWND ITEEN
// RAHCT ENEUD RETNH AEOEI FOLSE  DTIWE NHAET OYTEY QHEEN CTAYC
// REIFT BRSPA MHHEW ENATA MATEG  YEERL BIEEF OASFI OTUET UAEOT
// OARMA EERTN RTIBS EDDNI AAHTT  MSTEW PIERO AGRIE WFEBA ECTDD
// HILOE IHSIT EGOEA OSDDR YDLCR  ITRKL MLEHA GTDHA RDPNE OHMGF
// WFEUH EECDM RIPFE IMEHN LSSTT  RTVDO HW

// OBKRU OXOGH ULBSO LIFBB WFLRV  QQPRN GKSSO IWTQS JQSSE KZZWA
// TJKLU DXYWI NFBNY PVTTM ZFPEW  GDKZX TJCDI GXXXU AUEKC AR


// some code based off [Rosetta Code Vigenére Cipher](http://rosettacode.org/wiki/Vigen%C3%A8re_cipher#Rust) 

fn to_sanitized_bytes(string: &str) -> Vec<u8> {
    string.chars()
          .filter(|&c| c.is_alphabetic())
          .map(|c| c.to_ascii_uppercase() as u8)
          .collect::<Vec<u8>>()
}

// prepend the key, then append the remainder of the alphabet
fn get_vigenere_alphabet (alphabet_key: &str) -> String {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string().chars().filter(|&a| !alphabet_key.contains(a)).collect::<String>();
    let mut ret: String = String::new();
    ret.push_str(alphabet_key);
    ret.push_str(&alphabet);
    ret
}

// get the string for the row of the `offset_char`.
fn get_substitution_alphabet (original_alphabet: String, offset_char: char) -> String {
    let mut found = String::with_capacity(original_alphabet.len());
    let mut vector_index: usize = 0;

    for (i, c) in original_alphabet.chars().enumerate() {
        if c == offset_char {
            vector_index = i as usize;
            found.push_str(&original_alphabet[vector_index..]);
            found.push_str(&original_alphabet[..vector_index]);
            break;
        }
    }

    found
}

// convert a string to a vector of integer offsets; [0] is the index where "A" is stored, [25] is the index where "Z" is stored
fn alphabet_to_int_vector (alphabet: String) -> Vec<u8> {
    let mut int_alphabet: Vec<u8> = vec![0;alphabet.len()];
    for (pos, element) in alphabet.chars().enumerate() {
        int_alphabet[(element as u8 - ASCII_A) as usize] = pos as u8;
    }
    int_alphabet
}


struct Vigenere {
    alphabet: String,
}
impl Vigenere {
    fn translate (&self, input: &str, key: &str, is_encoding: bool) -> String {
        let mut mappings: Vec<Vec<u8>> = Vec::new();
        let mut alphabets: Vec<String> = Vec::new();
        let alphabet_len = self.alphabet.len();
        let input_bytes = to_sanitized_bytes(input);
        let key_bytes = to_sanitized_bytes(key);
        let key_len = key_bytes.len();
        let mut output = String::with_capacity(input_bytes.len());
        let v_int = alphabet_to_int_vector(self.alphabet.clone());

        for a in key.chars() {
            let mut this_vec: Vec<u8> = Vec::new();
            let this_offset: u8 = v_int[(a as u8 - ASCII_A) as usize];
            alphabets.push(get_substitution_alphabet(self.alphabet.clone(), a));
            for this_int in alphabet_to_int_vector(self.alphabet.clone()) {
                let this_diff: u8 = (alphabet_len as u8 + this_int - this_offset) % alphabet_len as u8;
                this_vec.push(this_diff);
            }
            mappings.push(this_vec);
        }

        for i in 0..input_bytes.len() {
            let this_char = input_bytes[i];
            let input_index = v_int[(this_char as u8 - ASCII_A) as usize];
            let this_alphabet = &alphabets[i % key_len];

            if is_encoding {
                output.push_str(&this_alphabet[input_index as usize..(input_index + 1) as usize]);
            }
        }
        output
    }
    fn encode (&self, plaintext: &str, key: &str) -> String {
        self.translate(plaintext, key, true)
    }
    fn decode (&self, ciphertext: &str, key: &str) -> String {
        self.translate(ciphertext, key, false)
    }
}

fn main() {
    let possible_actions = ["encode", "decode"];
    let cli_flags = App::new("kryptos-rs")
                          .version("1.0")
                          .author("David Wortham <djwortham@gmail.com>")
                          .arg(Arg::from_usage("--action=[ACTION] 'encode or decode?'").possible_values(&possible_actions))
                          .arg(Arg::from_usage("--alphabet=[KRYPTOS] 'Vigenére alphabet keyword'"))
                          .arg(Arg::from_usage("--key-phrase=[KEY] 'Vigenére key phrase'"))
                          .arg(Arg::from_usage("--input=[INPUT] 'Vigenére input text (plaintext if encoding; ciphertext if decoding)'"))
                          .get_matches();

    if cli_flags.is_present("action") && cli_flags.is_present("alphabet") && cli_flags.is_present("key-phrase") && cli_flags.is_present("input") {

        let alphabet_key = cli_flags.value_of("alphabet").unwrap();
        let plaintext = cli_flags.value_of("input").unwrap();
        let key_string = cli_flags.value_of("key-phrase").unwrap();

        println!("plaintext: {}; key: {}", plaintext, key_string);
        // println!("ciphertext: {}", get_cipher_text());

        let alphabet : String = get_vigenere_alphabet(alphabet_key);
        let v = Vigenere {alphabet: alphabet.clone()};
        let encoded = match cli_flags.value_of("action").unwrap_or("") {
            "encode" => v.encode(&plaintext, &key_string),
            "decode" => v.decode(&plaintext, &key_string),
            // "" => None,
            _ => v.encode(&plaintext, &key_string),
        };
        println!("vigenere encoded: {}", encoded);
    }
}