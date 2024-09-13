//! This file contains some code to represent the regions that althea exits are in for geolocking
//! a library would be better but this is a small enough amount of code that it's not worth it
//! Note this list was completed using AI so it may not be 100% accurate. I've hand checked the major countries
//! but if you see an issue just open a PR.

use serde::Serialize;
use serde::{Deserialize, Deserializer, Serializer};
use std::convert::Infallible;
use std::{
    fmt::{self, Display},
    str::FromStr,
};

/// An enum representation of the Regions supported by althea exits
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Regions {
    UnitedStates,
    Canada,
    Mexico,
    Argentina,
    Bolivia,
    Brazil,
    Chile,
    Colombia,
    Ecuador,
    Guyana,
    Paraguay,
    Peru,
    Suriname,
    Uruguay,
    Venezuela,
    Albania,
    Andorra,
    Armenia,
    Austria,
    Azerbaijan,
    Belarus,
    Belgium,
    BosniaAndHerzegovina,
    Bulgaria,
    Croatia,
    Cyprus,
    CzechRepublic,
    Denmark,
    Estonia,
    Finland,
    France,
    Georgia,
    Germany,
    Greece,
    Hungary,
    Iceland,
    Ireland,
    Italy,
    Kazakhstan,
    Kosovo,
    Latvia,
    Liechtenstein,
    Lithuania,
    Luxembourg,
    Malta,
    Moldova,
    Monaco,
    Montenegro,
    Netherlands,
    NorthMacedonia,
    Norway,
    Poland,
    Portugal,
    Romania,
    Russia,
    SanMarino,
    Serbia,
    Slovakia,
    Slovenia,
    Spain,
    Sweden,
    Switzerland,
    Turkey,
    Ukraine,
    UnitedKingdom,
    VaticanCity,
    UnkownRegion,
    Algeria,
    Angola,
    Benin,
    Botswana,
    BurkinaFaso,
    Burundi,
    CaboVerde,
    Cameroon,
    CentralAfricanRepublic,
    Chad,
    Comoros,
    Congo,
    DemocraticRepublicOfTheCongo,
    Djibouti,
    Egypt,
    EquatorialGuinea,
    Eritrea,
    Eswatini,
    Ethiopia,
    Gabon,
    Gambia,
    Ghana,
    Guinea,
    GuineaBissau,
    IvoryCoast,
    Kenya,
    Lesotho,
    Liberia,
    Libya,
    Madagascar,
    Malawi,
    Mali,
    Mauritania,
    Mauritius,
    Morocco,
    Mozambique,
    Namibia,
    Niger,
    Nigeria,
    Rwanda,
    SaoTomeAndPrincipe,
    Senegal,
    Seychelles,
    SierraLeone,
    Somalia,
    SouthAfrica,
    SouthSudan,
    Sudan,
    Tanzania,
    Togo,
    Tunisia,
    Uganda,
    Zambia,
    Zimbabwe,
    Afghanistan,
    Bahrain,
    Bangladesh,
    Bhutan,
    Brunei,
    Cambodia,
    China,
    EastTimor,
    India,
    Indonesia,
    Iran,
    Iraq,
    Israel,
    Japan,
    Jordan,
    Kuwait,
    Kyrgyzstan,
    Laos,
    Lebanon,
    Malaysia,
    Maldives,
    Mongolia,
    Myanmar,
    Nepal,
    NorthKorea,
    Oman,
    Pakistan,
    Palestine,
    Philippines,
    Qatar,
    SaudiArabia,
    Singapore,
    SouthKorea,
    SriLanka,
    Syria,
    Taiwan,
    Tajikistan,
    Thailand,
    Turkmenistan,
    UnitedArabEmirates,
    Uzbekistan,
    Vietnam,
    Yemen,
    Australia,
    NewZealand,
    AntiguaAndBarbuda,
    Bahamas,
    Barbados,
    Belize,
    Cuba,
    Dominica,
    DominicanRepublic,
    Grenada,
    Haiti,
    Jamaica,
    SaintKittsAndNevis,
    SaintLucia,
    SaintVincentAndTheGrenadines,
    TrinidadAndTobago,
}

/// Internal mapping of a region to an integer, used to store data in the db
impl From<Regions> for u8 {
    fn from(value: Regions) -> Self {
        match value {
            Regions::UnitedStates => 1,
            Regions::Canada => 2,
            Regions::Ghana => 3,
            Regions::Mexico => 4,
            Regions::Nigeria => 5,
            Regions::Colombia => 6,
            Regions::Senegal => 7,
            Regions::Seychelles => 8,
            Regions::SierraLeone => 9,
            Regions::Somalia => 10,
            Regions::SouthAfrica => 11,
            Regions::SouthSudan => 12,
            Regions::Sudan => 13,
            Regions::Tanzania => 14,
            Regions::Togo => 15,
            Regions::Tunisia => 16,
            Regions::Uganda => 17,
            Regions::Zambia => 18,
            Regions::Zimbabwe => 19,
            Regions::Afghanistan => 20,
            Regions::Bahrain => 21,
            Regions::Bangladesh => 22,
            Regions::Bhutan => 23,
            Regions::Brunei => 24,
            Regions::Cambodia => 25,
            Regions::China => 26,
            Regions::EastTimor => 27,
            Regions::India => 28,
            Regions::Indonesia => 29,
            Regions::Iran => 30,
            Regions::Iraq => 31,
            Regions::Israel => 32,
            Regions::Japan => 33,
            Regions::Jordan => 34,
            Regions::Kuwait => 35,
            Regions::Kyrgyzstan => 36,
            Regions::Laos => 37,
            Regions::Lebanon => 38,
            Regions::Malaysia => 39,
            Regions::Maldives => 40,
            Regions::Mongolia => 41,
            Regions::Myanmar => 42,
            Regions::Nepal => 43,
            Regions::NorthKorea => 44,
            Regions::Oman => 45,
            Regions::Pakistan => 46,
            Regions::Palestine => 47,
            Regions::Philippines => 48,
            Regions::Qatar => 49,
            Regions::SaudiArabia => 50,
            Regions::Singapore => 51,
            Regions::SouthKorea => 52,
            Regions::SriLanka => 53,
            Regions::Syria => 54,
            Regions::Taiwan => 55,
            Regions::Tajikistan => 56,
            Regions::Thailand => 57,
            Regions::Turkmenistan => 58,
            Regions::UnitedArabEmirates => 59,
            Regions::Uzbekistan => 60,
            Regions::Vietnam => 61,
            Regions::Yemen => 62,
            Regions::Australia => 63,
            Regions::NewZealand => 64,
            Regions::AntiguaAndBarbuda => 65,
            Regions::Bahamas => 66,
            Regions::Barbados => 67,
            Regions::Belize => 68,
            Regions::Cuba => 69,
            Regions::Dominica => 70,
            Regions::DominicanRepublic => 71,
            Regions::Grenada => 72,
            Regions::Haiti => 73,
            Regions::Jamaica => 74,
            Regions::SaintKittsAndNevis => 75,
            Regions::SaintLucia => 76,
            Regions::SaintVincentAndTheGrenadines => 77,
            Regions::TrinidadAndTobago => 78,
            Regions::UnkownRegion => 0,
            Regions::Argentina => 79,
            Regions::Bolivia => 80,
            Regions::Brazil => 81,
            Regions::Chile => 82,
            Regions::Ecuador => 83,
            Regions::Guyana => 84,
            Regions::Paraguay => 85,
            Regions::Peru => 86,
            Regions::Suriname => 87,
            Regions::Uruguay => 88,
            Regions::Venezuela => 89,
            Regions::Albania => 90,
            Regions::Andorra => 91,
            Regions::Armenia => 92,
            Regions::Austria => 93,
            Regions::Azerbaijan => 94,
            Regions::Belarus => 95,
            Regions::Belgium => 96,
            Regions::BosniaAndHerzegovina => 97,
            Regions::Bulgaria => 98,
            Regions::Croatia => 99,
            Regions::Cyprus => 100,
            Regions::CzechRepublic => 101,
            Regions::Denmark => 102,
            Regions::Estonia => 103,
            Regions::Finland => 104,
            Regions::France => 105,
            Regions::Georgia => 106,
            Regions::Germany => 107,
            Regions::Greece => 108,
            Regions::Hungary => 109,
            Regions::Iceland => 110,
            Regions::Ireland => 111,
            Regions::Italy => 112,
            Regions::Kazakhstan => 113,
            Regions::Kosovo => 114,
            Regions::Latvia => 115,
            Regions::Liechtenstein => 116,
            Regions::Lithuania => 117,
            Regions::Luxembourg => 118,
            Regions::Malta => 119,
            Regions::Moldova => 120,
            Regions::Monaco => 121,
            Regions::Montenegro => 122,
            Regions::Netherlands => 123,
            Regions::NorthMacedonia => 124,
            Regions::Norway => 125,
            Regions::Poland => 126,
            Regions::Portugal => 127,
            Regions::Romania => 128,
            Regions::Russia => 129,
            Regions::SanMarino => 130,
            Regions::Serbia => 131,
            Regions::Slovakia => 132,
            Regions::Slovenia => 133,
            Regions::Spain => 134,
            Regions::Sweden => 135,
            Regions::Switzerland => 136,
            Regions::Turkey => 137,
            Regions::Ukraine => 138,
            Regions::UnitedKingdom => 139,
            Regions::VaticanCity => 140,
            Regions::Algeria => 141,
            Regions::Angola => 142,
            Regions::Benin => 143,
            Regions::Botswana => 144,
            Regions::BurkinaFaso => 145,
            Regions::Burundi => 146,
            Regions::CaboVerde => 147,
            Regions::Cameroon => 148,
            Regions::CentralAfricanRepublic => 149,
            Regions::Chad => 150,
            Regions::Comoros => 151,
            Regions::Congo => 152,
            Regions::DemocraticRepublicOfTheCongo => 153,
            Regions::Djibouti => 154,
            Regions::Egypt => 155,
            Regions::EquatorialGuinea => 156,
            Regions::Eritrea => 157,
            Regions::Eswatini => 158,
            Regions::Ethiopia => 159,
            Regions::Gabon => 160,
            Regions::Gambia => 161,
            Regions::Guinea => 162,
            Regions::GuineaBissau => 163,
            Regions::IvoryCoast => 164,
            Regions::Kenya => 165,
            Regions::Lesotho => 166,
            Regions::Liberia => 167,
            Regions::Libya => 168,
            Regions::Madagascar => 169,
            Regions::Malawi => 170,
            Regions::Mali => 171,
            Regions::Mauritania => 172,
            Regions::Mauritius => 173,
            Regions::Morocco => 174,
            Regions::Mozambique => 175,
            Regions::Namibia => 176,
            Regions::Niger => 177,
            Regions::Rwanda => 178,
            Regions::SaoTomeAndPrincipe => 179,
        }
    }
}

impl From<u8> for Regions {
    fn from(value: u8) -> Self {
        match value {
            1 => Regions::UnitedStates,
            2 => Regions::Canada,
            3 => Regions::Ghana,
            4 => Regions::Mexico,
            5 => Regions::Nigeria,
            6 => Regions::Colombia,
            7 => Regions::Senegal,
            8 => Regions::Seychelles,
            9 => Regions::SierraLeone,
            10 => Regions::Somalia,
            11 => Regions::SouthAfrica,
            12 => Regions::SouthSudan,
            13 => Regions::Sudan,
            14 => Regions::Tanzania,
            15 => Regions::Togo,
            16 => Regions::Tunisia,
            17 => Regions::Uganda,
            18 => Regions::Zambia,
            19 => Regions::Zimbabwe,
            20 => Regions::Afghanistan,
            21 => Regions::Bahrain,
            22 => Regions::Bangladesh,
            23 => Regions::Bhutan,
            24 => Regions::Brunei,
            25 => Regions::Cambodia,
            26 => Regions::China,
            27 => Regions::EastTimor,
            28 => Regions::India,
            29 => Regions::Indonesia,
            30 => Regions::Iran,
            31 => Regions::Iraq,
            32 => Regions::Israel,
            33 => Regions::Japan,
            34 => Regions::Jordan,
            35 => Regions::Kuwait,
            36 => Regions::Kyrgyzstan,
            37 => Regions::Laos,
            38 => Regions::Lebanon,
            39 => Regions::Malaysia,
            40 => Regions::Maldives,
            41 => Regions::Mongolia,
            42 => Regions::Myanmar,
            43 => Regions::Nepal,
            44 => Regions::NorthKorea,
            45 => Regions::Oman,
            46 => Regions::Pakistan,
            47 => Regions::Palestine,
            48 => Regions::Philippines,
            49 => Regions::Qatar,
            50 => Regions::SaudiArabia,
            51 => Regions::Singapore,
            52 => Regions::SouthKorea,
            53 => Regions::SriLanka,
            54 => Regions::Syria,
            55 => Regions::Taiwan,
            56 => Regions::Tajikistan,
            57 => Regions::Thailand,
            58 => Regions::Turkmenistan,
            59 => Regions::UnitedArabEmirates,
            60 => Regions::Uzbekistan,
            61 => Regions::Vietnam,
            62 => Regions::Yemen,
            63 => Regions::Australia,
            64 => Regions::NewZealand,
            65 => Regions::AntiguaAndBarbuda,
            66 => Regions::Bahamas,
            67 => Regions::Barbados,
            68 => Regions::Belize,
            69 => Regions::Cuba,
            70 => Regions::Dominica,
            71 => Regions::DominicanRepublic,
            72 => Regions::Grenada,
            73 => Regions::Haiti,
            74 => Regions::Jamaica,
            75 => Regions::SaintKittsAndNevis,
            76 => Regions::SaintLucia,
            77 => Regions::SaintVincentAndTheGrenadines,
            78 => Regions::TrinidadAndTobago,
            79 => Regions::Argentina,
            80 => Regions::Bolivia,
            81 => Regions::Brazil,
            82 => Regions::Chile,
            83 => Regions::Ecuador,
            84 => Regions::Guyana,
            85 => Regions::Paraguay,
            86 => Regions::Peru,
            87 => Regions::Suriname,
            88 => Regions::Uruguay,
            89 => Regions::Venezuela,
            90 => Regions::Albania,
            91 => Regions::Andorra,
            92 => Regions::Armenia,
            93 => Regions::Austria,
            94 => Regions::Azerbaijan,
            95 => Regions::Belarus,
            96 => Regions::Belgium,
            97 => Regions::BosniaAndHerzegovina,
            98 => Regions::Bulgaria,
            99 => Regions::Croatia,
            100 => Regions::Cyprus,
            101 => Regions::CzechRepublic,
            102 => Regions::Denmark,
            103 => Regions::Estonia,
            104 => Regions::Finland,
            105 => Regions::France,
            106 => Regions::Georgia,
            107 => Regions::Germany,
            108 => Regions::Greece,
            109 => Regions::Hungary,
            110 => Regions::Iceland,
            111 => Regions::Ireland,
            112 => Regions::Italy,
            113 => Regions::Kazakhstan,
            114 => Regions::Kosovo,
            115 => Regions::Latvia,
            116 => Regions::Liechtenstein,
            117 => Regions::Lithuania,
            118 => Regions::Luxembourg,
            119 => Regions::Malta,
            120 => Regions::Moldova,
            121 => Regions::Monaco,
            122 => Regions::Montenegro,
            123 => Regions::Netherlands,
            124 => Regions::NorthMacedonia,
            125 => Regions::Norway,
            126 => Regions::Poland,
            127 => Regions::Portugal,
            128 => Regions::Romania,
            129 => Regions::Russia,
            130 => Regions::SanMarino,
            131 => Regions::Serbia,
            132 => Regions::Slovakia,
            133 => Regions::Slovenia,
            134 => Regions::Spain,
            135 => Regions::Sweden,
            136 => Regions::Switzerland,
            137 => Regions::Turkey,
            138 => Regions::Ukraine,
            139 => Regions::UnitedKingdom,
            140 => Regions::VaticanCity,
            141 => Regions::Algeria,
            142 => Regions::Angola,
            143 => Regions::Benin,
            144 => Regions::Botswana,
            145 => Regions::BurkinaFaso,
            146 => Regions::Burundi,
            147 => Regions::CaboVerde,
            148 => Regions::Cameroon,
            149 => Regions::CentralAfricanRepublic,
            150 => Regions::Chad,
            151 => Regions::Comoros,
            152 => Regions::Congo,
            153 => Regions::DemocraticRepublicOfTheCongo,
            154 => Regions::Djibouti,
            155 => Regions::Egypt,
            156 => Regions::EquatorialGuinea,
            157 => Regions::Eritrea,
            158 => Regions::Eswatini,
            159 => Regions::Ethiopia,
            160 => Regions::Gabon,
            161 => Regions::Gambia,
            162 => Regions::Guinea,
            163 => Regions::GuineaBissau,
            164 => Regions::IvoryCoast,
            165 => Regions::Kenya,
            166 => Regions::Lesotho,
            167 => Regions::Liberia,
            168 => Regions::Libya,
            169 => Regions::Madagascar,
            170 => Regions::Malawi,
            171 => Regions::Mali,
            172 => Regions::Mauritania,
            173 => Regions::Mauritius,
            174 => Regions::Morocco,
            175 => Regions::Mozambique,
            176 => Regions::Namibia,
            177 => Regions::Niger,
            178 => Regions::Rwanda,
            179 => Regions::SaoTomeAndPrincipe,
            _ => Regions::UnkownRegion,
        }
    }
}

impl Display for Regions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Regions::UnitedStates => write!(f, "United States"),
            Regions::Canada => write!(f, "Canada"),
            Regions::Ghana => write!(f, "Ghana"),
            Regions::Nigeria => write!(f, "Nigeria"),
            Regions::Colombia => write!(f, "Colombia"),
            Regions::Mexico => write!(f, "Mexico"),
            Regions::UnkownRegion => write!(f, "Unknown Region"),
            Regions::Argentina => write!(f, "Argentina"),
            Regions::Bolivia => write!(f, "Bolivia"),
            Regions::Brazil => write!(f, "Brazil"),
            Regions::Chile => write!(f, "Chile"),
            Regions::Ecuador => write!(f, "Ecuador"),
            Regions::Guyana => write!(f, "Guyana"),
            Regions::Paraguay => write!(f, "Paraguay"),
            Regions::Peru => write!(f, "Peru"),
            Regions::Suriname => write!(f, "Suriname"),
            Regions::Uruguay => write!(f, "Uruguay"),
            Regions::Venezuela => write!(f, "Venezuela"),
            Regions::Albania => write!(f, "Albania"),
            Regions::Andorra => write!(f, "Andorra"),
            Regions::Armenia => write!(f, "Armenia"),
            Regions::Austria => write!(f, "Austria"),
            Regions::Azerbaijan => write!(f, "Azerbaijan"),
            Regions::Belarus => write!(f, "Belarus"),
            Regions::Belgium => write!(f, "Belgium"),
            Regions::BosniaAndHerzegovina => write!(f, "Bosnia and Herzegovina"),
            Regions::Bulgaria => write!(f, "Bulgaria"),
            Regions::Croatia => write!(f, "Croatia"),
            Regions::Cyprus => write!(f, "Cyprus"),
            Regions::CzechRepublic => write!(f, "Czech Republic"),
            Regions::Denmark => write!(f, "Denmark"),
            Regions::Estonia => write!(f, "Estonia"),
            Regions::Finland => write!(f, "Finland"),
            Regions::France => write!(f, "France"),
            Regions::Georgia => write!(f, "Georgia"),
            Regions::Germany => write!(f, "Germany"),
            Regions::Greece => write!(f, "Greece"),
            Regions::Hungary => write!(f, "Hungary"),
            Regions::Iceland => write!(f, "Iceland"),
            Regions::Ireland => write!(f, "Ireland"),
            Regions::Italy => write!(f, "Italy"),
            Regions::Kazakhstan => write!(f, "Kazakhstan"),
            Regions::Kosovo => write!(f, "Kosovo"),
            Regions::Latvia => write!(f, "Latvia"),
            Regions::Liechtenstein => write!(f, "Liechtenstein"),
            Regions::Lithuania => write!(f, "Lithuania"),
            Regions::Luxembourg => write!(f, "Luxembourg"),
            Regions::Malta => write!(f, "Malta"),
            Regions::Moldova => write!(f, "Moldova"),
            Regions::Monaco => write!(f, "Monaco"),
            Regions::Montenegro => write!(f, "Montenegro"),
            Regions::Netherlands => write!(f, "Netherlands"),
            Regions::NorthMacedonia => write!(f, "North Macedonia"),
            Regions::Norway => write!(f, "Norway"),
            Regions::Poland => write!(f, "Poland"),
            Regions::Portugal => write!(f, "Portugal"),
            Regions::Romania => write!(f, "Romania"),
            Regions::Russia => write!(f, "Russia"),
            Regions::SanMarino => write!(f, "San Marino"),
            Regions::Serbia => write!(f, "Serbia"),
            Regions::Slovakia => write!(f, "Slovakia"),
            Regions::Slovenia => write!(f, "Slovenia"),
            Regions::Spain => write!(f, "Spain"),
            Regions::Sweden => write!(f, "Sweden"),
            Regions::Switzerland => write!(f, "Switzerland"),
            Regions::Turkey => write!(f, "Turkey"),
            Regions::Ukraine => write!(f, "Ukraine"),
            Regions::UnitedKingdom => write!(f, "United Kingdom"),
            Regions::VaticanCity => write!(f, "Vatican City"),
            Regions::Algeria => write!(f, "Algeria"),
            Regions::Angola => write!(f, "Angola"),
            Regions::Benin => write!(f, "Benin"),
            Regions::Botswana => write!(f, "Botswana"),
            Regions::BurkinaFaso => write!(f, "Burkina Faso"),
            Regions::Burundi => write!(f, "Burundi"),
            Regions::CaboVerde => write!(f, "Cabo Verde"),
            Regions::Cameroon => write!(f, "Cameroon"),
            Regions::CentralAfricanRepublic => write!(f, "Central African Republic"),
            Regions::Chad => write!(f, "Chad"),
            Regions::Comoros => write!(f, "Comoros"),
            Regions::Congo => write!(f, "Congo"),
            Regions::DemocraticRepublicOfTheCongo => write!(f, "Democratic Republic of the Congo"),
            Regions::Djibouti => write!(f, "Djibouti"),
            Regions::Egypt => write!(f, "Egypt"),
            Regions::EquatorialGuinea => write!(f, "Equatorial Guinea"),
            Regions::Eritrea => write!(f, "Eritrea"),
            Regions::Eswatini => write!(f, "Eswatini"),
            Regions::Ethiopia => write!(f, "Ethiopia"),
            Regions::Gabon => write!(f, "Gabon"),
            Regions::Gambia => write!(f, "Gambia"),
            Regions::Guinea => write!(f, "Guinea"),
            Regions::GuineaBissau => write!(f, "Guinea-Bissau"),
            Regions::IvoryCoast => write!(f, "Ivory Coast"),
            Regions::Kenya => write!(f, "Kenya"),
            Regions::Lesotho => write!(f, "Lesotho"),
            Regions::Liberia => write!(f, "Liberia"),
            Regions::Libya => write!(f, "Libya"),
            Regions::Madagascar => write!(f, "Madagascar"),
            Regions::Malawi => write!(f, "Malawi"),
            Regions::Mali => write!(f, "Mali"),
            Regions::Mauritania => write!(f, "Mauritania"),
            Regions::Mauritius => write!(f, "Mauritius"),
            Regions::Morocco => write!(f, "Morocco"),
            Regions::Mozambique => write!(f, "Mozambique"),
            Regions::Namibia => write!(f, "Namibia"),
            Regions::Niger => write!(f, "Niger"),
            Regions::Rwanda => write!(f, "Rwanda"),
            Regions::SaoTomeAndPrincipe => write!(f, "Sao Tome and Principe"),
            Regions::Senegal => write!(f, "Senegal"),
            Regions::Seychelles => write!(f, "Seychelles"),
            Regions::SierraLeone => write!(f, "Sierra Leone"),
            Regions::Somalia => write!(f, "Somalia"),
            Regions::SouthAfrica => write!(f, "South Africa"),
            Regions::SouthSudan => write!(f, "South Sudan"),
            Regions::Sudan => write!(f, "Sudan"),
            Regions::Tanzania => write!(f, "Tanzania"),
            Regions::Togo => write!(f, "Togo"),
            Regions::Tunisia => write!(f, "Tunisia"),
            Regions::Uganda => write!(f, "Uganda"),
            Regions::Zambia => write!(f, "Zambia"),
            Regions::Zimbabwe => write!(f, "Zimbabwe"),
            Regions::Afghanistan => write!(f, "Afghanistan"),
            Regions::Bahrain => write!(f, "Bahrain"),
            Regions::Bangladesh => write!(f, "Bangladesh"),
            Regions::Bhutan => write!(f, "Bhutan"),
            Regions::Brunei => write!(f, "Brunei"),
            Regions::Cambodia => write!(f, "Cambodia"),
            Regions::China => write!(f, "China"),
            Regions::EastTimor => write!(f, "East Timor"),
            Regions::India => write!(f, "India"),
            Regions::Indonesia => write!(f, "Indonesia"),
            Regions::Iran => write!(f, "Iran"),
            Regions::Iraq => write!(f, "Iraq"),
            Regions::Israel => write!(f, "Israel"),
            Regions::Japan => write!(f, "Japan"),
            Regions::Jordan => write!(f, "Jordan"),
            Regions::Kuwait => write!(f, "Kuwait"),
            Regions::Kyrgyzstan => write!(f, "Kyrgyzstan"),
            Regions::Laos => write!(f, "Laos"),
            Regions::Lebanon => write!(f, "Lebanon"),
            Regions::Malaysia => write!(f, "Malaysia"),
            Regions::Maldives => write!(f, "Maldives"),
            Regions::Mongolia => write!(f, "Mongolia"),
            Regions::Myanmar => write!(f, "Myanmar"),
            Regions::Nepal => write!(f, "Nepal"),
            Regions::NorthKorea => write!(f, "North Korea"),
            Regions::Oman => write!(f, "Oman"),
            Regions::Pakistan => write!(f, "Pakistan"),
            Regions::Palestine => write!(f, "Palestine"),
            Regions::Philippines => write!(f, "Philippines"),
            Regions::Qatar => write!(f, "Qatar"),
            Regions::SaudiArabia => write!(f, "Saudi Arabia"),
            Regions::Singapore => write!(f, "Singapore"),
            Regions::SouthKorea => write!(f, "South Korea"),
            Regions::SriLanka => write!(f, "Sri Lanka"),
            Regions::Syria => write!(f, "Syria"),
            Regions::Taiwan => write!(f, "Taiwan"),
            Regions::Tajikistan => write!(f, "Tajikistan"),
            Regions::Thailand => write!(f, "Thailand"),
            Regions::Turkmenistan => write!(f, "Turkmenistan"),
            Regions::UnitedArabEmirates => write!(f, "United Arab Emirates"),
            Regions::Uzbekistan => write!(f, "Uzbekistan"),
            Regions::Vietnam => write!(f, "Vietnam"),
            Regions::Yemen => write!(f, "Yemen"),
            Regions::Australia => write!(f, "Australia"),
            Regions::NewZealand => write!(f, "New Zealand"),
            Regions::AntiguaAndBarbuda => write!(f, "Antigua and Barbuda"),
            Regions::Bahamas => write!(f, "Bahamas"),
            Regions::Barbados => write!(f, "Barbados"),
            Regions::Belize => write!(f, "Belize"),
            Regions::Cuba => write!(f, "Cuba"),
            Regions::Dominica => write!(f, "Dominica"),
            Regions::DominicanRepublic => write!(f, "Dominican Republic"),
            Regions::Grenada => write!(f, "Grenada"),
            Regions::Haiti => write!(f, "Haiti"),
            Regions::Jamaica => write!(f, "Jamaica"),
            Regions::SaintKittsAndNevis => write!(f, "Saint Kitts and Nevis"),
            Regions::SaintLucia => write!(f, "Saint Lucia"),
            Regions::SaintVincentAndTheGrenadines => write!(f, "Saint Vincent and the Grenadines"),
            Regions::TrinidadAndTobago => write!(f, "Trinidad and Tobago"),
        }
    }
}

impl FromStr for Regions {
    type Err = Infallible;
    fn from_str(s: &str) -> Result<Regions, Infallible> {
        let lowercase_s = s.to_lowercase();
        for i in 0..Regions::NUM_REGIONS {
            let region = Regions::from(i);
            if region.to_string().to_lowercase() == lowercase_s {
                return Ok(region);
            }
        }
        Ok(Regions::UnkownRegion)
    }
}

impl Regions {
    pub const NUM_REGIONS: u8 = 179;
}

impl Serialize for Regions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Regions {
    fn deserialize<D>(deserializer: D) -> Result<Regions, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod test {
    use super::Regions;

    /// The number of current valid regions
    const NUM_REGIONS: u8 = 179;

    #[test]
    fn string_serialize_and_parse() {
        for i in 0..NUM_REGIONS {
            let region = Regions::from(i);
            let region_str = region.to_string();
            let parsed_region: Regions = region_str.parse().unwrap();
            assert_eq!(region, parsed_region);
        }
    }

    #[test]
    fn integer_serialize_and_parse() {
        for i in 0..NUM_REGIONS {
            let region = Regions::from(i);
            let region_num_2: u8 = region.into();
            assert_eq!(i, region_num_2);
        }
    }
}
