//
// Language data, sorted by number of native speakers
// https://en.wikipedia.org/wiki/List_of_languages_by_number_of_native_speakers
// fields: code, name, english name, right to left?
//

const DATA = {
  zh: ['zh', '中文', 'Chinese'],
  es: ['es', 'Español', 'Spanish'],
  en: ['en', 'English'],
  hi: ['hi', 'हिन्दी', 'Hindi'],
  ar: ['ar', 'العربية', 'Arabic', true],
  pt: ['pt', 'Português', 'Portugues'],
  bn: ['bn', 'বাংলা', 'Bengali'],
  ru: ['ru', 'Pyccĸий', 'Russian'],
  ja: ['ja', '日本語', 'Japanese'],
  pa: ['pa', 'ਪੰਜਾਬੀ', 'Punjabi'],
  de: ['de', 'Deutsch', 'German'],
  ms: ['ms', 'بهاس ملايو', 'Malay'],
  te: ['te', 'తెలుగు', 'Telugu'],
  vi: ['vi', 'Tiếng Việt', 'Vietnamese'],
  ko: ['ko', '한국어', 'Korean'],
  fr: ['fr', 'Français', 'French'],
  mr: ['mr', 'मराठी', 'Marathi'],
  ta: ['ta', 'தமிழ்', 'Tamil'],
  ur: ['ur', 'اُردُو', 'Urdu'],
  fa: ['fa', 'فارسی', 'Farsi'],
  tr: ['tr', 'Türkçe', 'Turkish'],
  it: ['it', 'Italiano', 'Italian'],
  th: ['th', 'ภาษาไทย', 'Thai'],
  gu: ['gu', 'Gujarati'],
  pl: ['pl', 'Polski', 'Polish'],
  ml: ['ml', 'Malayalam'],
  uk: ['uk', 'Ukrainian'],
  sw: ['sw', 'Swahili'],
  uz: ['uz', 'Uzbek'],
  ro: ['ro', 'Romanian'],
  nl: ['nl', 'Nederlands', 'Dutch'],
  sr: ['sr', 'Serbian'],
  el: ['el', 'Ελληνικά', 'Greek'],
  ca: ['ca', 'Català', 'Catalan'],
  he: ['he', 'עברית', 'Hebrew', true],
  sl: ['sl', 'Slovenščina', 'Slovenian'],
  lt: ['lt', 'Lietuvių kalba', 'Lithuanian']
}

export default class Language {

  constructor(data_entry) {
    this.code = data_entry[0] || 'xx'
    this.name = data_entry[1]  || '????'
    this.en_name = data_entry[2] || '????'
    this.rtl = data_entry[3]
  }

  static find(code) {
    return new Language(DATA[code])
  }

}
