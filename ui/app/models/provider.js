import bitmask from 'lib/bitmask'

var LOCALE = 'en'

export default class Provider {

  constructor(props) {
    this._name = props.name
    this._description = props.description
    let k = null
    for (k in props) {
      if (k != 'description' && k != 'name') {
        this[k] = props[k]
      }
    }
  }

  get name() {
    return this._name[LOCALE]
  }

  get description() {
    return this._description[LOCALE]
  }

  static setup(domain) {
    return bitmask.bonafide.provider.create(domain).then(
      response => {
        console.log("Provider configured: " + response.domain)
        return new Provider(response)
      }
    )
  }

  static get(domain) {
    return bitmask.bonafide.provider.read(domain).then(
      response => {
        return new Provider(response)
      }
    )
  }

  static list(seeded=false) {
    return bitmask.bonafide.provider.list(seeded).then(
      response => {
        return response.map(
          i => { return i['domain'] }
        )
      }
    )
  }

  static delete(domain) {
    return bitmask.bonafide.provider.delete(domain)
  }
}



