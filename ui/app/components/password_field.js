//
// A validating password field, with a label and error messages.
//

import React from 'react'
import { FormGroup, ControlLabel, FormControl, HelpBlock} from 'react-bootstrap'
import Validate from 'lib/validate'

export default class PasswordField extends React.Component {

  static get defaultProps() {return{
    id: null,                // required. controlId of the element
    label: "Password",
    onChange: null,          // callback passed current password
    validationMode: "crack", // one of 'none', 'match', 'crack'
    matchText: null,         // used if validationMode == 'match'
  }}

  constructor(props) {
    super(props)
    this.state = {
      password: null,       // password value
      passwordState: null,  // password validation state
      passwordError: false, // password help message
    }
    this.keypress = this.keypress.bind(this)
  }

  componentDidMount() {
    if (this.props.validationMode == 'crack') {
      Validate.loadPasswdLib()
    }
  }

  render() {
    let passwordHelp = null

    if (this.state.passwordError) {
      passwordHelp = <HelpBlock>{this.state.passwordError}</HelpBlock>
    }

    return (
      <FormGroup controlId={this.props.id} validationState={this.state.passwordState}>
        <ControlLabel>{this.props.label}</ControlLabel>
        <FormControl
          type="password"
          ref="password"
          value={this.state.password || ""}
          onChange={this.keypress} />
        {this.state.passwordState == 'success' ? null : <FormControl.Feedback/>}
        {passwordHelp}
      </FormGroup>
     )
  }

  keypress(e) {
    let password = e.target.value
    if (this.props.onChange) {
      this.props.onChange(password)
    }
    this.setState({password: password})
    if (this.props.validationMode == 'crack') {
      if (password.length > 0) {
        this.validateCrack(password)
      } else {
        this.setState({
          passwordState: null,
          passwordError: null
        })
      }
    } else if (this.props.validationMode == 'match') {
      this.validateMatch(password)
    }
  }

  validateCrack(password) {
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
  }

  validateMatch(password) {
    if (this.props.matchText) {
      if (password != this.props.matchText) {
        this.setState({
          passwordState: 'error',
          passwordError: "Does not match"
        })
      } else {
        this.setState({
          passwordState: 'success',
          passwordError: null
        })
      }
    }
  }

}
