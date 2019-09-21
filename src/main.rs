extern crate cipher_crypt;
extern crate clap;

use cipher_crypt::{Cipher, ColumnarTransposition, Vigenere};
use clap::{Arg, App};


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


#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_vigenere_encode() {
        let v = Vigenere::new(String::from("giovan"));
        assert_eq!("O vsqee mmh vnl izsyig!", v.encrypt("I never get any credit!").unwrap());
    }

    #[test]
    fn test_vigenere_decode() {
        let v = Vigenere::new(String::from("giovan"));
        assert_eq!("I never get any credit!", v.decrypt("O vsqee mmh vnl izsyig!").unwrap());
    }

    #[test]
    fn test_coumnartransposition_encode() {
        let v = ColumnarTransposition::new((String::from("zebras"), None));
        assert_eq!("respce!uemeers-taSs g", v.encrypt("Super-secret message!").unwrap());
    }

    #[test]
    fn test_coumnartransposition_decode() {
        let v = ColumnarTransposition::new((String::from("zebras"), None));
        assert_eq!("Super-secret message!", v.decrypt("respce!uemeers-taSs g").unwrap());
    }
}


fn main() {
    let possible_actions = ["encode", "decode"];
    let cli_flags = App::new("kryptos-rs")
                          .version("1.0")
                          .author("David Wortham <djwortham@gmail.com>")
                          .arg(Arg::from_usage("--action=[ACTION] 'encode or decode?'").possible_values(&possible_actions))
                          .arg(Arg::from_usage("--key-phrase=[KEY] 'Vigenére key phrase'"))
                          .arg(Arg::from_usage("--input=[INPUT] 'Vigenére input text (plaintext if encoding; ciphertext if decoding)'"))
                          .get_matches();

    if cli_flags.is_present("action") && cli_flags.is_present("key-phrase") && cli_flags.is_present("input") {

        let plaintext = cli_flags.value_of("input").unwrap();
        let key_string = cli_flags.value_of("key-phrase").unwrap();

        println!("plaintext: {}; key: {}", plaintext, key_string);

        let v = Vigenere::new(String::from(key_string));
        let encoded = match cli_flags.value_of("action").unwrap_or("") {
            "encode" => v.encrypt(&plaintext).unwrap(),
            "decode" => v.decrypt(&plaintext).unwrap(),
            _ => v.encrypt(&plaintext).unwrap(),
        };
        println!("vigenere encoded: {}", String::from(encoded));
    }
}
