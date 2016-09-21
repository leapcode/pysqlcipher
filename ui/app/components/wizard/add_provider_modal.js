//
// A modal popup to add a new provider.
//

import React from 'react'
import { FormGroup, ControlLabel, FormControl, HelpBlock, Button, ButtonToolbar, Modal } from 'react-bootstrap'

import Spinner from 'components/spinner'
import Validate from 'lib/validate'
import Provider from 'models/provider'

export default class AddProviderModal extends React.Component {

  static get defaultProps() {return{
    title: 'Add a provider',
    onClose: null
  }}

  constructor(props) {
    super(props)
    this.state = {
      validationState: null,  // one of 'success', 'error', 'warning'
      errorMsg: null,
      domain: "",
      working: false,         // true if waiting for something
    }
    this.accept   = this.accept.bind(this)
    this.cancel   = this.cancel.bind(this)
    this.changed  = this.changed.bind(this)
  }

  accept(e=null) {
    if (e) {
      e.preventDefault() // don't reload the page please!
    }
    if (this.state.domain) {
      this.setState({working: true})
      Provider.setup(this.state.domain).then(
        provider => {
          this.props.onClose(provider)
          // this.setState({working: false})
        },
        error => {
          this.setState({
            validationState: 'warning',
            errorMsg: error,
            working: false
          })
        }
      )
    }
  }

  cancel() {
    this.props.onClose()
  }

  changed(e) {
    let domain = e.target.value
    let newState = null
    let newMsg   = null

    if (domain.length > 0) {
      let msg = Validate.domain(domain)
      newState = msg ? 'error' : 'success'
      newMsg   = msg
    }
    this.setState({
      domain: domain,
      validationState: newState,
      errorMsg: newMsg
    })
  }

  render() {
    let help = null
    let addButton = null
    if (this.state.errorMsg) {
      help = <HelpBlock>{this.state.errorMsg}</HelpBlock>
    } else {
      help = <HelpBlock>&nbsp;</HelpBlock>
    }
    if (this.state.working) {
      addButton = <Button><Spinner /></Button>
    } else if (this.state.validationState == 'warning') {
      addButton = <Button onClick={this.accept}>Retry</Button>
    } else if (this.state.validationState == 'error') {
      addButton = <Button disabled={true}>Add</Button>
    } else {
      addButton = <Button onClick={this.accept}>Add</Button>
    }
    let form = <form onSubmit={this.accept} autoComplete="off">
      <FormGroup controlId="addprovider" validationState={this.state.validationState}>
        <ControlLabel>Domain</ControlLabel>
        <FormControl
          type="text"
          ref="domain"
          autoFocus
          value={this.state.domain}
          onChange={this.changed}
          onBlur={this.changed} />
        {help}
      </FormGroup>
      <ButtonToolbar>
        {addButton}
        <Button onClick={this.cancel}>Cancel</Button>
      </ButtonToolbar>
    </form>

    return(
      <Modal show={true} onHide={this.cancel}>
        <Modal.Header closeButton>
          <Modal.Title>{this.props.title}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {form}
        </Modal.Body>
      </Modal>
    )
  }
}
