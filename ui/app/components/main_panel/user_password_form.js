//
// A form to change the user password
//

import React from 'react'
import { Button, Glyphicon, Alert } from 'react-bootstrap'
import Spinner from 'components/spinner'
import PasswordField from 'components/password_field'
import Account from 'models/account'
import bitmask from 'lib/bitmask'

export default class UserPasswordForm extends React.Component {

  static get defaultProps() {return{
    account: null,
  }}

  constructor(props) {
    super(props)
    this.state = {
      error: null,
      message: null,
      loading: false,
      currentPassword: null,
      newPassword: null,
      repeatPassword: null
    }
    this.submit = this.submit.bind(this)
    this.setNew = this.setNew.bind(this)
    this.setCurrent = this.setCurrent.bind(this)
    this.setRepeat = this.setRepeat.bind(this)
  }

  setCurrent(value) {
    this.setState({currentPassword: value})
  }

  setNew(value) {
    this.setState({newPassword: value})
  }

  setRepeat(value) {
    this.setState({repeatPassword: value})
  }

  submit(e) {
    e.preventDefault() // don't reload the page please!
    if (!this.maySubmit()) { return }
    this.setState({loading: true})
    bitmask.bonafide.user.update(
      this.props.account.address,
      this.state.currentPassword,
      this.state.newPassword).then(
      response => {
        this.setState({
          currentPassword: null,
          newPassword: null,
          repeatPassword: null,
          message: response,
          error: null,
          loading: false
        })
      }, error => {
        this.setState({
          error: error,
          message: null,
          loading: false
        })
      }
    )
  }

  maySubmit() {
    return (
      !this.state.loading &&
      this.state.currentPassword &&
      this.state.newPassword &&
      this.state.newPassword == this.state.repeatPassword
    )
  }

  render () {
    let submitButton = null
    let message = null

    // style may be: success, warning, danger, info
    if (this.state.error) {
      message = (
        <Alert bsStyle="danger">{this.state.error}</Alert>
      )
    } else if (this.state.message) {
      message = (
        <Alert bsStyle="success">{this.state.message}</Alert>
      )
    }

    if (this.state.loading) {
      submitButton = <Button block disabled={true}><Spinner /></Button>
    } else {
      submitButton = <Button block disabled={!this.maySubmit()} onClick={this.submit}>Change</Button>
    }
    return (
      <form onSubmit={this.submit}>
        {message}
        <PasswordField id={this.props.account.id + "-current-password"}
          label="Current Password"
          validationMode="none"
          onChange={this.setCurrent} />
        <PasswordField id={this.props.account.id + "-new-password"}
          label="New Password"
          validationMode="crack"
          onChange={this.setNew} />
        <PasswordField id={this.props.account.id + "-repeat-password"}
          label="Repeat Password"
          validationMode="match"
          matchText={this.state.newPassword}
          onChange={this.setRepeat} />
        {submitButton}
      </form>
    )
  }

}
