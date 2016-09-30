import React from 'react'
import { Button, Glyphicon, Alert } from 'react-bootstrap'
import SectionLayout from './section_layout'
import UserPasswordForm from './user_password_form'

import Login from 'components/login'
import Spinner from 'components/spinner'
import Account from 'models/account'

import bitmask from 'lib/bitmask'

export default class UserSection extends React.Component {

  static get defaultProps() {return{
    account: null,
    onLogout: null,
    onLogin: null
  }}

  constructor(props) {
    super(props)
    this.state = {
      error: null,
      loading: false,
      expanded: false,
    }
    this.logout = this.logout.bind(this)
    this.expand = this.expand.bind(this)
  }

  logout() {
    this.setState({loading: true})
    this.props.account.logout().then(
      account => {
        this.setState({error: null, loading: false})
        if (this.props.onLogout) {
          this.props.onLogout(account)
        }
      }, error => {
        this.setState({error: error, loading: false})
      }
    )
  }

  expand() {
    this.setState({expanded: !this.state.expanded})
  }

  render () {
    if (this.props.account.authenticated) {
      return this.renderAccount()
    } else {
      return this.renderLoginForm()
    }
  }

  renderAccount() {
    let button = null
    let message = null
    let body = null
    let header = <h1>{this.props.account.address}</h1>

    if (this.state.error) {
      // style may be: success, warning, danger, info
      message = (
        <Alert bsStyle="danger">{this.state.error}</Alert>
      )
    }
    if (this.state.expanded) {
      body = <UserPasswordForm account={this.props.account} />
    }
    if (this.state.loading) {
      button = <Button disabled={true}><Spinner /></Button>
    } else {
      button = <Button onClick={this.logout}>Log Out</Button>
    }

    return (
      <SectionLayout icon="user" buttons={button} status="on"
        onExpand={this.expand} header={header} body={body} message={message} />
    )
  }

  renderLoginForm() {
    let address = null
    if (this.props.account.userpart) {
      address = this.props.account.address
    }
    let header = (
      <Login
        onLogin={this.props.onLogin}
        domain={this.props.account.domain}
        address={address}
      />
    )
    return (
      <SectionLayout icon="user" className="wide-margin" header={header}/>
    )
  }

}
