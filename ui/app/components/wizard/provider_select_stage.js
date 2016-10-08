import React from 'react'
import {Button, ButtonGroup, ButtonToolbar, Glyphicon} from 'react-bootstrap'

import App from 'app'
import Provider from 'models/provider'
import Language from 'lib/language'

import ListEditor from 'components/list_editor'
import {HorizontalLayout, Column} from 'components/layout'

import StageLayout from './stage_layout'
import AddProviderModal from './add_provider_modal'

const SERVICE_MAP = {
  mx: "Mail",
  openvpn: "VPN",
  chat: "Chat"
}

export default class ProviderSelectStage extends React.Component {

  static get defaultProps() {return{
    title: "Choose a provider",
    initialProvider: null
  }}

  constructor(props) {
    super(props)
    this.state = {
      domains: [],        // array of domains, as strings
      showModal: false,
      selected: null,     // domain of selected item
      provider: null,     // Provider object, if selected
      error: null         // error message
    }
    this.add      = this.add.bind(this)
    this.remove   = this.remove.bind(this)
    this.select   = this.select.bind(this)
    this.close    = this.close.bind(this)
    this.cancel   = this.cancel.bind(this)
    this.next     = this.next.bind(this)
  }

  componentWillMount() {
    this.refreshList({
      provider: this.props.initialProvider,
      selected: (this.props.initialProvider ? this.props.initialProvider.domain : null)
    })
  }

  //
  // newState is the state to apply after
  // domains are refreshed
  //
  refreshList(newState=null) {
    Provider.list(true).then(domains => {
      this.setState(Object.assign({domains: domains}, newState))
      if (domains.length > 0) {
        let domain = this.state.selected
        if (domains.includes(domain)) {
          this.select(domain)
        } else {
          this.select(domains[0])
        }
      } else {
        this.select(null)
      }
    })
  }

  add() {
    this.setState({showModal: true})
  }

  remove(domain, newactive) {
    Provider.delete(domain).then(
      response => {
        this.refreshList({selected: newactive})
      },
      error => {
        console.log(error)
      }
    )
  }

  select(domain) {
    this.setState({
      selected: domain
    })
    if (domain) {
      Provider.get(domain).then(
        provider => {
          this.setState({
            provider: provider
          })
        },
        error => {
          this.setState({
            provider: null,
            error: error
          })
        }
      )
    } else {
      this.setState({
        provider: null,
        error: null
      })
    }
  }

  close(provider=null) {
    if (provider) {
      this.refreshList({
        showModal: false,
        provider: provider,
        selected: provider.domain
      })
    } else {
      this.setState({
        showModal: false
      })
    }
  }

  cancel() {
    App.start()
  }

  next() {
    App.show('wizard', {
      stage: 'register',
      provider: this.state.provider
    })
  }

  render() {
    let modal = null
    let info = null
    if (this.state.provider) {
      let languages = this.state.provider.languages.map(code => Language.find(code).name)
      let services = this.state.provider.services.map(code => SERVICE_MAP[code] || '????')
      info = (
        <div>
          <h1 className="first">{this.state.provider.name}</h1>
          <h3>{this.state.provider.domain}</h3>
          <p>{this.state.provider.description}</p>
          <p><b>Enrollment Policy:</b> {this.state.provider.enrollment_policy}</p>
          <p><b>Services</b>: {services.join(', ')}</p>
          <p><b>Languages</b>: {languages.join(', ')}</p>
        </div>
      )
    } else if (this.state.error) {
      info = <div>{this.state.error}</div>
    }
    if (this.state.showModal) {
      modal = <AddProviderModal onClose={this.close} />
    }
    let buttons = (
      <div>
        <ButtonToolbar className="pull-left">
          <Button onClick={this.cancel}>
            Cancel
          </Button>
        </ButtonToolbar>
        <ButtonToolbar className="pull-right">
          <Button onClick={this.next}>
            Next
            <Glyphicon glyph="chevron-right" />
          </Button>
        </ButtonToolbar>
      </div>
    )
    let editlist = <ListEditor ref="list" items={this.state.domains}
      selected={this.state.selected} onRemove={this.remove} onAdd={this.add}
      onSelect={this.select} />
    return(
      <StageLayout title={this.props.title} subtitle={this.props.subtitle} buttons={buttons}>
        <HorizontalLayout equalWidths={true}>
          <Column>{editlist}</Column>
          <Column>{info}</Column>
        </HorizontalLayout>
        {modal}
      </StageLayout>
    )
  }
}
