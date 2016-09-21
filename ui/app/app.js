import bitmask from 'lib/bitmask'
import Account from 'models/account'

class Application {
  constructor() {
  }

  //
  // main entry point for the application
  //
  initialize() {
    if (this.debugging()) {
      this.show(this.debug_panel)
    } else {
      this.start()
    }
  }

  start() {
    Account.active().then(account => {
      if (account == null) {
        this.show('greeter')
      } else {
        this.show('main', {initialAccount: account})
      }
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
}

var App = new Application
export default App