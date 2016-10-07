import bitmask from 'lib/bitmask'
import Account from 'models/account'
import Provider from 'models/provider'
import EventLogger from 'lib/event_logger'

class Application {
  constructor() {
  }

  //
  // main entry point for the application
  //
  initialize() {
    this.ev = new EventLogger()
    if (this.debugging()) {
      this.show(this.debug_panel)
    } else {
      this.start()
    }
  }

  start() {
    Provider.list(false).then(domains => {
      Account.initialize_list(domains)
      Account.active().then(account => {
        if (account == null) {
          this.show('greeter')
        } else {
          Account.add_primary(account)
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
}

var App = new Application
export default App