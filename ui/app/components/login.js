import React from 'react'
import ReactDOM from 'react-dom'

import { FormGroup, ControlLabel, FormControl, HelpBlock, Button,
  Checkbox, Glyphicon, Overlay, Tooltip, Alert } from 'react-bootstrap'
import Spinner from './spinner'

import Validate from 'lib/validate'
import App from 'app'
import Account from 'models/account'
import Provider from 'models/provider'

class Login extends React.Component {

  static get defaultProps() {return{
    rememberAllowed: false,   // if set, show remember password checkbox
    autoAllowed: false,       // if set, allow auto setup of provider
    domain: null,             // if set, only allow this domain
    address: null,            // if set, only allow this username@domain
    onLogin: null,            // callback
    mode: "login"             // one of "login" or "signup"
  }}

  constructor(props) {
    super(props)

    // validation states can be null, 'success', 'warning', or 'error'

    this.state = {
      loading: false,

      authError: false,     // authentication error message

      username: this.props.address,
      usernameState: null,  // username validation state
      usernameError: false, // username help message

      password: null,       // the main password field
      passwordState: null,  // password validation state
      passwordError: false, // password help message

      password2: null,       // password confirmation
      password2State: null,  // password confirm validation state
      password2Error: false, // password confirm help message

      requireInvite: false,
      invite: null,          // invite code value
      inviteState: null,     // invite code validation state
      inviteError: false,    // invite code error

      disabled: false,
      remember: false        // remember is checked?
    }

    // prebind:
    this.onUsernameChange = this.onUsernameChange.bind(this)
    this.onUsernameBlur   = this.onUsernameBlur.bind(this)
    this.onPassword  = this.onPassword.bind(this)
    this.onPassword2 = this.onPassword2.bind(this)
    this.onInvite    = this.onInvite.bind(this)
    this.onSubmit    = this.onSubmit.bind(this)
    this.onRemember  = this.onRemember.bind(this)
  }

  componentDidMount() {
    Validate.loadPasswdLib()
    if (this.props.domain && this.props.mode == 'signup') {
      Provider.get(this.props.domain).then(provider => {
        if (provider.enrollment_policy == 'invite') {
          this.setState({requireInvite: true})
        }
      })
    }
  }

  render () {
    let rememberCheck = ""
    let submitButton  = ""
    let usernameHelp  = null
    let passwordHelp  = null
    let password2Help  = null
    let password2Elem  = null
    let inviteElem  = null
    let message = null
    let buttonText = "Log In"

    /*
     * disabled for now
     *
    if (this.props.rememberAllowed) {
      let props = {
        style: {marginTop: "0px"},
        onChange: this.onRemember
      }

      if (this.state.remember) {
        rememberCheck = <Checkbox {...props} checked>
          Remember username and password
        </Checkbox>
      } else {
        rememberCheck = <Checkbox {...props}>
          Remember username and password
        </Checkbox>
      }
    }
    */

    if (this.state.authError) {
      // style may be: success, warning, danger, info
      message = (
        <Alert bsStyle="danger">{this.state.authError}</Alert>
      )
    }

    if (this.state.usernameError) {
      usernameHelp = <HelpBlock>{this.state.usernameError}</HelpBlock>
      // let props = {shouldUpdatePosition: true, show:true, placement:"right",
      //              target:this.refs.username}
      // usernameHelp = (
      //   <Overlay {...props}>
      //     <Tooltip id="username-tooltip">{this.state.usernameError}</Tooltip>
      //   </Overlay>
      // )
    } else {
      //usernameHelp = <HelpBlock>&nbsp;</HelpBlock>
    }

    if (this.state.passwordError) {
      passwordHelp = <HelpBlock>{this.state.passwordError}</HelpBlock>
      // let props = {shouldUpdatePosition: true, show:true, placement:"right",
      //              target:this.refs.password, component: {this}}
      // passwordHelp = (
      //   <Overlay {...props}>
      //     <Tooltip id="password-tooltip">{this.state.passwordError}</Tooltip>
      //   </Overlay>
      // )
    } else {
      //passwordHelp = <HelpBlock>&nbsp;</HelpBlock>
    }

    if (this.props.mode == 'signup') {
      buttonText = 'Sign Up'
      if (this.state.password2Error) {
        password2Help = <HelpBlock>{this.state.password2Error}</HelpBlock>
      }
      password2Elem = (
        <FormGroup controlId="loginPassword2" validationState={this.state.password2State}>
          <ControlLabel>Repeat Password</ControlLabel>
          <FormControl
            type="password"
            ref="password"
            value={this.state.password2 || ""}
            onChange={this.onPassword2} />
          {this.state.password2State == 'success' ? null : <FormControl.Feedback/>}
          {password2Help}
        </FormGroup>
      )
      if (this.state.requireInvite) {
        let inviteHelp = null
        inviteElem = (
          <FormGroup controlId="invite" validationState={this.state.inviteState}>
            <ControlLabel>Invite Code</ControlLabel>
            <FormControl
              value={this.state.invite || ""}
              onChange={this.onInvite} />
            {inviteHelp}
          </FormGroup>
        )
      }
    }

    let buttonProps = {
      type: "button",
      onClick: this.onSubmit,
      disabled: !this.maySubmit()
    }
    if (this.state.loading) {
       submitButton = <Button block {...buttonProps}><Spinner /></Button>
    } else {
       submitButton = <Button block {...buttonProps}>{buttonText}</Button>
    }

    let usernameref = null
    let usernameDisabled = false
    let usernameValue = this.state.username || ""
    if (this.props.address) {
      usernameDisabled = true
      usernameValue = this.props.address
    } else if (this.props.domain) {
      usernameref = function(c) {
        if (c != null) {
          let textarea = ReactDOM.findDOMNode(c)
          let start = textarea.value.indexOf('@')
          if (textarea.selectionStart > start) {
            textarea.setSelectionRange(start, start)
          }
        }
      }
    }

    let form = <form onSubmit={this.onSubmit}>
      {message}
      <FormGroup style={{marginBottom: '10px' }} controlId="loginUsername" validationState={this.state.usernameState}>
        <ControlLabel>Username</ControlLabel>
        <FormControl
          componentClass="textarea"
          style={{resize: "none"}}
          rows="1"
          ref={usernameref}
          autoFocus
          value={usernameValue}
          disabled={usernameDisabled}
          onChange={this.onUsernameChange}
          onBlur={this.onUsernameBlur} />
        {this.state.usernameState == 'success' ? null : <FormControl.Feedback/>}
        {usernameHelp}
      </FormGroup>

      <FormGroup controlId="loginPassword" validationState={this.state.passwordState}>
        <ControlLabel>Password</ControlLabel>
        <FormControl
          type="password"
          ref="password"
          value={this.state.password || ""}
          onChange={this.onPassword} />
        {this.state.passwordState == 'success' ? null : <FormControl.Feedback/>}
        {passwordHelp}
      </FormGroup>

      {password2Elem}
      {inviteElem}
      {submitButton}
      {rememberCheck}
    </form>

    return form
  }

  //
  // Here we do a partial validation, because the user has not stopped typing.
  //
  onUsernameChange(e) {
    let username = e.target.value.toLowerCase().replace("\n", "")
    if (this.props.domain) {
      let [userpart, domainpart] = username.split(
        new RegExp('@|' + this.props.domain.replace(".", "\\.") + '$')
      )
      username = [userpart, this.props.domain].join('@')
    }
    let error = Validate.usernameInteractive(username, this.props.domain)
    let state = null
    if (error) {
      state = 'error'
    } else {
      if (username && username.length > 0) {
        let finalError = Validate.username(username)
        state = finalError ? null : 'success'
      }
    }
    this.setState({
      username: username,
      usernameState: state,
      usernameError: error ? error : null
    })
  }

  //
  // Here we do a more complete validation, since the user have left the field.
  //
  onUsernameBlur(e) {
    let username = e.target.value.toLowerCase()
    this.setState({
      username: username
    })
    if (username.length > 0) {
      this.validateUsername(username)
    } else {
      this.setState({
        usernameState: null,
        usernameError: null
      })
    }
  }

  onPassword(e) {
    let password = e.target.value
    this.setState({password: password})
    if (password.length > 0) {
      this.validatePassword(password)
    } else {
      this.setState({
        passwordState: null,
        passwordError: null
      })
    }
  }

  onPassword2(e) {
    let password2 = e.target.value
    this.setState({password2: password2})
    this.validatePassword2(password2, this.state.password)
  }

  onInvite(e) {
    this.setState({invite: e.target.value})
  }

  onRemember(e) {
    let currentValue = e.target.value == 'on' ? true : false
    let value = !currentValue
    this.setState({remember: value})
  }

  validateUsername(username) {
    let error = Validate.username(username, this.props.domain)
    this.setState({
      usernameState: error ? 'error' : 'success',
      usernameError: error ? error : null
    })
  }

  validatePassword(password) {
    let state = null
    let message = null
    let result = Validate.passwordStrength(password)
    if (result) {
      message = "Time to crack: " + result.crack_times_display.offline_slow_hashing_1e4_per_second
      if (result.score == 0) {
        state = 'error'
      } else if (result.score == 1 || result.score == 2) {
        state = 'warning'
      } else {
        state = 'success'
      }
    }
    this.setState({
      passwordState: state,
      passwordError: message
    })
    this.validatePassword2(this.state.password2, password)
  }

  validatePassword2(password2, password) {
    if (password2) {
      if (password != password2) {
        this.setState({
          password2State: 'error',
          password2Error: "Does not match"
        })
      } else {
        this.setState({
          password2State: 'success',
          password2Error: null
        })
      }
    } else {
      this.setState({
        password2State: null,
        password2Error: null
      })
    }
  }

  maySubmit() {
    let ok = (
      !this.state.loading &&
      !this.state.usernameError &&
      this.state.username &&
      this.state.password
    )

    if (this.props.mode == 'login') {
      return ok
    } else if (this.props.mode == 'signup') {
      return ok &&
             this.state.password2 == this.state.password &&
             (!this.state.requireInvite || this.state.invite)
    }
  }

  onSubmit(e) {
    e.preventDefault() // don't reload the page please!
    if (!this.maySubmit()) { return }
    this.setState({loading: true})

    if (this.props.mode == 'login') {
      this.doLogin()
    } else if (this.props.mode == 'signup') {
      this.doSignup()
    }
  }

  doLogin() {
    let account = Account.findOrAdd(this.state.username)
    account.login(this.state.password, this.props.autoAllowed).then(
      account => {
        this.setState({loading: false})
        if (this.props.onLogin) {
          this.props.onLogin(account)
        }
      },
      error => {
        if (error == "") {
          error = "Something failed, but we did not get a message"
        }
        this.setState({
          loading: false,
          usernameState: 'error',
          passwordState: 'error',
          authError: error
        })
      }
    )
  }

  doSignup() {
    Account.create(
      this.state.username,
      this.state.password,
      this.state.invite
    ).then(
      account => {
        this.doLogin()
      },
      error => {
        if (error == "") {
          error = "Something failed, but we did not get a message"
        }
        // error messages for invite codes are in english, and
        // hardcoded in leap_web in the file invite_code_validator.rb
        // all the code error messages have the word 'code' in them.
        // the api backend is returning {user: {code: "error message"}}
        // but that structure is lost by the time it reaches us.
        if (/code/.test(error)) {
          this.setState({
            loading: false,
            inviteState: 'error',
            authError: error
          })
        } else {
          this.setState({
            loading: false,
            usernameState: 'error',
            passwordState: 'error',
            authError: error
          })
        }
      }
    )
  }

}

export default Login