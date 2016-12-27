import bitmask from 'lib/bitmask'
import Account from 'models/account'
import Provider from 'models/provider'

class Application {
  constructor() {
  }

  //
  // main entry point for the application
  //
  initialize() {
    window.addEventListener("error", this.handleError.bind(this))
    window.addEventListener("unhandledrejection", this.handleError.bind(this))
    if (this.debugging()) {
      this.show(this.debug_panel)
    } else {
      this.start()
    }
  }

  start() {
    Provider.list(false).then(domains => {
      Account.initializeList(domains)
      Account.active().then(account => {
        if (account == null) {
          this.show('greeter')
        } else {
          Account.addPrimary(account)
          this.show('main', {initialAccount: account})
        }
      }, error => {
        this.show('error', {error: error})
      })
    }, error => {
      this.show('error', {error: error})
    })
  }

  show(panel, properties) {
    this.switcher.show(panel, properties)
  }

  debugging() {
    this.debug_panel = window.location.hash.replace('#', '')
    return this.debug_panel && this.debug_panel != 'main'
  }

  handleError(e) {
    this.show('error', {error: e})
  }
}

var App = new Application
export default App