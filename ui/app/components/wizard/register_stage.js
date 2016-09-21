import React from 'react'
import {Button, ButtonGroup, ButtonToolbar,
        Glyphicon, Tabs, Tab} from 'react-bootstrap'

import App from 'app'
import Provider from 'models/provider'
import Login from 'components/login'
import Center from 'components/center'

import StageLayout from './stage_layout'

export default class RegisterStage extends React.Component {

  static get defaultProps() {return{
    provider: null
  }}

  constructor(props) {
    super(props)
    this.state = {
      activeTab:   'signup',   // either 'login' or 'signup'
      error: null       // error message
    }
    // this.add      = this.add.bind(this)
    // this.remove   = this.remove.bind(this)
    // this.select   = this.select.bind(this)
    this.selectTab = this.selectTab.bind(this)
    this.previous = this.previous.bind(this)
    this.cancel = this.cancel.bind(this)
    this.login = this.login.bind(this)
  }

  previous() {
    App.show('wizard', {
      stage: 'provider',
      initialProvider: this.props.provider
    })
  }

  cancel() {
    App.start()
  }

  login(account) {
    App.show('main', {initialAccount: account})
  }

  selectTab(key) {
    this.setState({
      activeTab: key
    })
  }

  render() {
    let info = null
    if (this.props.provider) {
      info = (
        <div>
          <h1 className="first">{this.props.provider.name}</h1>
          <h3>{this.props.provider.domain}</h3>
          <p>{this.props.provider.description}</p>
          <p><b>Enrollment Policy:</b> {this.props.provider.enrollment_policy}</p>
          <p><b>Services</b>: {this.props.provider.services}</p>
          <p><b>Languages</b>: {this.props.provider.languages.join(', ')}</p>
        </div>
      )
    }
    let buttons = (
      <div>
        <ButtonToolbar className="pull-left">
          <Button onClick={this.cancel}>
            Cancel
          </Button>
        </ButtonToolbar>
        <ButtonToolbar className="pull-right">
          <Button onClick={this.previous}>
            <Glyphicon glyph="chevron-left" />
            Previous
          </Button>
        </ButtonToolbar>
      </div>
    )
    return(
      <StageLayout title={this.props.provider.domain} buttons={buttons}>
        <Tabs activeKey={this.state.activeTab} onSelect={this.selectTab} animation={false} id="login-tabs">
          <Tab eventKey="signup" title="Sign up">
            <div className="vspacer" />
            <Center direction="horizontal" width={400}>
              <Login mode="signup" domain={this.props.provider.domain} onLogin={this.login} />
            </Center>
          </Tab>
          <Tab eventKey="login" title="Log In">
            <div className="vspacer" />
            <Center direction="horizontal" width={400}>
              <Login domain={this.props.provider.domain} onLogin={this.login} />
            </Center>
          </Tab>
        </Tabs>
      </StageLayout>
    )
  }
}
