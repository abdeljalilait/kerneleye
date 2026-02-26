import { Globe } from 'lucide-react'
// Country flags
import US from 'country-flag-icons/react/3x2/US'
import GB from 'country-flag-icons/react/3x2/GB'
import CA from 'country-flag-icons/react/3x2/CA'
import AU from 'country-flag-icons/react/3x2/AU'
import DE from 'country-flag-icons/react/3x2/DE'
import FR from 'country-flag-icons/react/3x2/FR'
import IT from 'country-flag-icons/react/3x2/IT'
import ES from 'country-flag-icons/react/3x2/ES'
import NL from 'country-flag-icons/react/3x2/NL'
import RU from 'country-flag-icons/react/3x2/RU'
import CN from 'country-flag-icons/react/3x2/CN'
import JP from 'country-flag-icons/react/3x2/JP'
import KR from 'country-flag-icons/react/3x2/KR'
import IN from 'country-flag-icons/react/3x2/IN'
import BR from 'country-flag-icons/react/3x2/BR'
import MX from 'country-flag-icons/react/3x2/MX'
import SG from 'country-flag-icons/react/3x2/SG'
import HK from 'country-flag-icons/react/3x2/HK'
import TW from 'country-flag-icons/react/3x2/TW'
import CH from 'country-flag-icons/react/3x2/CH'
import SE from 'country-flag-icons/react/3x2/SE'
import NO from 'country-flag-icons/react/3x2/NO'
import DK from 'country-flag-icons/react/3x2/DK'
import FI from 'country-flag-icons/react/3x2/FI'
import PL from 'country-flag-icons/react/3x2/PL'
import CZ from 'country-flag-icons/react/3x2/CZ'
import AT from 'country-flag-icons/react/3x2/AT'
import BE from 'country-flag-icons/react/3x2/BE'
import IE from 'country-flag-icons/react/3x2/IE'
import PT from 'country-flag-icons/react/3x2/PT'
import GR from 'country-flag-icons/react/3x2/GR'
import TR from 'country-flag-icons/react/3x2/TR'
import UA from 'country-flag-icons/react/3x2/UA'
import RO from 'country-flag-icons/react/3x2/RO'
import HU from 'country-flag-icons/react/3x2/HU'
import IL from 'country-flag-icons/react/3x2/IL'
import AE from 'country-flag-icons/react/3x2/AE'
import SA from 'country-flag-icons/react/3x2/SA'
import ZA from 'country-flag-icons/react/3x2/ZA'
import NG from 'country-flag-icons/react/3x2/NG'
import EG from 'country-flag-icons/react/3x2/EG'
import PK from 'country-flag-icons/react/3x2/PK'
import BD from 'country-flag-icons/react/3x2/BD'
import ID from 'country-flag-icons/react/3x2/ID'
import TH from 'country-flag-icons/react/3x2/TH'
import VN from 'country-flag-icons/react/3x2/VN'
import MY from 'country-flag-icons/react/3x2/MY'
import PH from 'country-flag-icons/react/3x2/PH'
import NZ from 'country-flag-icons/react/3x2/NZ'
import CL from 'country-flag-icons/react/3x2/CL'
import CO from 'country-flag-icons/react/3x2/CO'
import AR from 'country-flag-icons/react/3x2/AR'
import PE from 'country-flag-icons/react/3x2/PE'
import VE from 'country-flag-icons/react/3x2/VE'
import EC from 'country-flag-icons/react/3x2/EC'
import UY from 'country-flag-icons/react/3x2/UY'
import PY from 'country-flag-icons/react/3x2/PY'
import BO from 'country-flag-icons/react/3x2/BO'

// Country flag components map
const flagComponents: Record<string, React.FC<{ style?: React.CSSProperties }>> = {
  US, GB, CA, AU, DE, FR, IT, ES, NL, RU, CN, JP, KR, IN, BR, MX, SG, HK, TW,
  CH, SE, NO, DK, FI, PL, CZ, AT, BE, IE, PT, GR, TR, UA, RO, HU, IL, AE, SA,
  ZA, NG, EG, PK, BD, ID, TH, VN, MY, PH, NZ, CL, CO, AR, PE, VE, EC, UY, PY, BO,
}

// Map of common country names to codes
const countryMap: Record<string, string> = {
  'united states': 'US', 'usa': 'US', 'united kingdom': 'GB', 'uk': 'GB',
  'germany': 'DE', 'france': 'FR', 'italy': 'IT', 'spain': 'ES', 'netherlands': 'NL',
  'russia': 'RU', 'russian federation': 'RU', 'china': 'CN', 'japan': 'JP',
  'south korea': 'KR', 'korea': 'KR', 'korea, republic of': 'KR', 'india': 'IN',
  'brazil': 'BR', 'mexico': 'MX', 'singapore': 'SG', 'hong kong': 'HK',
  'taiwan': 'TW', 'taiwan, province of china': 'TW', 'switzerland': 'CH',
  'sweden': 'SE', 'norway': 'NO', 'denmark': 'DK', 'finland': 'FI', 'poland': 'PL',
  'czech republic': 'CZ', 'czechia': 'CZ', 'austria': 'AT', 'belgium': 'BE',
  'ireland': 'IE', 'portugal': 'PT', 'greece': 'GR', 'turkey': 'TR', 'türkiye': 'TR',
  'ukraine': 'UA', 'romania': 'RO', 'hungary': 'HU', 'israel': 'IL',
  'united arab emirates': 'AE', 'saudi arabia': 'SA', 'south africa': 'ZA',
  'nigeria': 'NG', 'egypt': 'EG', 'pakistan': 'PK', 'bangladesh': 'BD',
  'indonesia': 'ID', 'thailand': 'TH', 'vietnam': 'VN', 'viet nam': 'VN',
  'malaysia': 'MY', 'philippines': 'PH', 'new zealand': 'NZ', 'chile': 'CL',
  'colombia': 'CO', 'argentina': 'AR', 'peru': 'PE', 'venezuela': 'VE',
  'venezuela, bolivarian republic of': 'VE', 'ecuador': 'EC', 'uruguay': 'UY',
  'paraguay': 'PY', 'bolivia': 'BO', 'bolivia, plurinational state of': 'BO',
  'canada': 'CA', 'australia': 'AU', 'spain': 'ES', 'estonia': 'EE',
  'latvia': 'LV', 'lithuania': 'LT', 'slovakia': 'SK', 'slovenia': 'SI',
  'croatia': 'HR', 'bulgaria': 'BG', 'serbia': 'RS', 'bosnia and herzegovina': 'BA',
  'north macedonia': 'MK', 'albania': 'AL', 'montenegro': 'ME', 'moldova': 'MD',
  'belarus': 'BY', 'armenia': 'AM', 'azerbaijan': 'AZ', 'georgia': 'GE',
  'kazakhstan': 'KZ', 'uzbekistan': 'UZ', 'kyrgyzstan': 'KG', 'tajikistan': 'TJ',
  'turkmenistan': 'TM', 'mongolia': 'MN', 'nepal': 'NP', 'sri lanka': 'LK',
  'myanmar': 'MM', 'cambodia': 'KH', 'laos': 'LA', 'brunei': 'BN', 'bhutan': 'BT',
  'maldives': 'MV', 'afghanistan': 'AF', 'iran': 'IR', 'iran, islamic republic of': 'IR',
  'iraq': 'IQ', 'syria': 'SY', 'syrian arab republic': 'SY', 'jordan': 'JO',
  'lebanon': 'LB', 'kuwait': 'KW', 'bahrain': 'BH', 'qatar': 'QA', 'oman': 'OM',
  'yemen': 'YE', 'libya': 'LY', 'tunisia': 'TN', 'algeria': 'DZ', 'morocco': 'MA',
  'sudan': 'SD', 'ethiopia': 'ET', 'kenya': 'KE', 'tanzania': 'TZ',
  'tanzania, united republic of': 'TZ', 'uganda': 'UG', 'rwanda': 'RW',
  'burundi': 'BI', 'somalia': 'SO', 'djibouti': 'DJ', 'eritrea': 'ER',
  'ghana': 'GH', 'ivory coast': 'CI', 'côte d\'ivoire': 'CI', 'senegal': 'SN',
  'mali': 'ML', 'burkina faso': 'BF', 'niger': 'NE', 'chad': 'TD', 'cameroon': 'CM',
  'central african republic': 'CF', 'equatorial guinea': 'GQ', 'gabon': 'GA',
  'congo': 'CG', 'democratic republic of the congo': 'CD', 'angola': 'AO',
  'zambia': 'ZM', 'zimbabwe': 'ZW', 'botswana': 'BW', 'namibia': 'NA',
  'mozambique': 'MZ', 'madagascar': 'MG', 'mauritius': 'MU', 'seychelles': 'SC',
  'comoros': 'KM', 'cape verde': 'CV', 'são tomé and príncipe': 'ST',
  'guinea': 'GN', 'guinea-bissau': 'GW', 'sierra leone': 'SL', 'liberia': 'LR',
  'togo': 'TG', 'benin': 'BJ', 'the gambia': 'GM', 'gambia': 'GM',
  'puerto rico': 'PR', 'cuba': 'CU', 'dominican republic': 'DO', 'haiti': 'HT',
  'jamaica': 'JM', 'trinidad and tobago': 'TT', 'barbados': 'BB', 'bahamas': 'BS',
  'belize': 'BZ', 'guatemala': 'GT', 'honduras': 'HN', 'el salvador': 'SV',
  'nicaragua': 'NI', 'costa rica': 'CR', 'panama': 'PA', 'venezuela': 'VE',
  'guyana': 'GY', 'suriname': 'SR', 'french guiana': 'GF', 'ecuador': 'EC',
  'colombia': 'CO', 'peru': 'PE', 'bolivia': 'BO', 'paraguay': 'PY',
  'uruguay': 'UY', 'chile': 'CL', 'argentina': 'AR', 'falkland islands': 'FK',
  'isle of man': 'IM', 'jersey': 'JE', 'guernsey': 'GG', 'monaco': 'MC',
  'liechtenstein': 'LI', 'andorra': 'AD', 'san marino': 'SM', 'vatican city': 'VA',
  'malta': 'MT', 'cyprus': 'CY', 'luxembourg': 'LU', 'iceland': 'IS',
  'faroe islands': 'FO', 'greenland': 'GL', 'svalbard and jan mayen': 'SJ',
  'gibraltar': 'GI', 'bermuda': 'BM', 'cayman islands': 'KY', 'british virgin islands': 'VG',
  'anguilla': 'AI', 'montserrat': 'MS', 'turks and caicos islands': 'TC',
  'aruba': 'AW', 'curaçao': 'CW', 'sint maarten': 'SX', 'bonaire': 'BQ',
  'saba': 'BQ', 'sint eustatius': 'BQ', 'new caledonia': 'NC', 'french polynesia': 'PF',
  'wallis and futuna': 'WF', 'norfolk island': 'NF', 'christmas island': 'CX',
  'cocos (keeling) islands': 'CC', 'pitcairn islands': 'PN', 'niue': 'NU',
  'cook islands': 'CK', 'tokelau': 'TK', 'tuvalu': 'TV', 'nauru': 'NR',
  'palau': 'PW', 'micronesia': 'FM', 'federated states of micronesia': 'FM',
  'marshall islands': 'MH', 'kiribati': 'KI', 'samoa': 'WS', 'american samoa': 'AS',
  'tonga': 'TO', 'vanuatu': 'VU', 'solomon islands': 'SB', 'papua new guinea': 'PG',
  'east timor': 'TL', 'timor-leste': 'TL', 'brunei darussalam': 'BN',
}

/**
 * Normalize country code from various formats
 */
export const normalizeCountryCode = (country: string): string => {
  if (!country) return ''
  // Already a 2-letter code
  if (/^[A-Za-z]{2}$/.test(country)) return country.toUpperCase()
  
  // Look up in map
  const normalized = country.toLowerCase().trim()
  return countryMap[normalized] || ''
}

interface CountryFlagProps {
  countryCode: string
  size?: number
  className?: string
}

/**
 * Country Flag Component
 * Displays a country flag based on country code or name
 */
export const CountryFlag: React.FC<CountryFlagProps> = ({ 
  countryCode, 
  size = 12,
  className 
}) => {
  const code = normalizeCountryCode(countryCode)
  if (!code) return <Globe size={size} style={{ opacity: 0.5 }} className={className} />
  
  const FlagComponent = flagComponents[code]
  if (!FlagComponent) return <Globe size={size} style={{ opacity: 0.5 }} className={className} />
  
  return (
    <FlagComponent 
      style={{ width: size * 1.5, height: size, borderRadius: 2 }} 
      className={className}
    />
  )
}

export default CountryFlag
