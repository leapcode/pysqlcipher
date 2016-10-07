//
// Button to show details for configuring mail clients
//

import React from 'react'
import { Modal, Form, FormGroup, ControlLabel, FormControl, Col, Label, Button} from 'react-bootstrap'
import Account from 'models/account'
import bitmask from 'lib/bitmask'

export default class IMAPButton extends React.Component {

  static get defaultProps() {return{
    account: null,
    title: "Connect Mail Client"
  }}

  constructor(props) {
    super(props)
    this.state = {
      showModal: false,
      imapPort: '1984',
      smtpPort: '2013',
      token: ''
    }
    this.onClick = this.onClick.bind(this)
    this.onClose = this.onClose.bind(this)
  }

  onClose() {
    this.setState({showModal: false})
  }

  onClick() {
    if (!this.state.token) {
      bitmask.mail.get_token().then(response => {
        if (response.user == this.props.account.address) {
          this.setState({token: response.token})
        }
      })
    }
    this.setState({showModal: true})
  }

  componentWillMount() {}

  // don't allow fields to be changed
  onChange() {}

  render () {
    let rowStyle = {height: '30px'} // to match bootstrap's input element height
    let form = null
    let modal = null

    if (this.state.showModal) {
      form = (
        <Form horizontal>
          <p>
             You can use any application that supports IMAP to read and send
             email through Bitmask.
          </p>
          <h3>Configuration for Thunderbird</h3>
          <p>
             For Thunderbird, you can use the Bitmask extension. Search for
             "Bitmask" in Thunderbird's add-on manager.
          </p>
          <h3>Configuration for other mail clients</h3>
          <p>
            Alternately, configure your mail client with the following options:
          </p>
          <FormGroup>
            <Col sm={2} componentClass={ControlLabel}>Username</Col>
            <Col sm={10}>
              <FormControl value={this.props.account.address} onChange={this.onChange}/>
            </Col>
          </FormGroup>
          <FormGroup>
            <Col sm={2} componentClass={ControlLabel}>Password</Col>
            <Col sm={10}>
              <FormControl value={this.state.token} onChange={this.onChange}/>
            </Col>
          </FormGroup>
          <FormGroup>
            <Col sm={2} componentClass={ControlLabel}>IMAP</Col>
            <Col sm={10} className="center-vertical" style={rowStyle}>
              <div className="center-item">
                <Label>Host</Label> localhost
                &nbsp;&nbsp;&nbsp;
                <Label>Port</Label> {this.state.imapPort}
              </div>
            </Col>
          </FormGroup>
          <FormGroup>
            <Col sm={2} componentClass={ControlLabel}>SMTP</Col>
            <Col sm={10} className="center-vertical" style={rowStyle}>
              <div className="center-item">
                <Label>Host</Label> localhost
                &nbsp;&nbsp;&nbsp;
                <Label>Port</Label> {this.state.smtpPort}
              </div>
            </Col>
          </FormGroup>
        </Form>
      )
      modal = (
        <Modal show={true} onHide={this.onClose}>
          <Modal.Header closeButton>
            <Modal.Title>{this.props.title}</Modal.Title>
          </Modal.Header>
           <Modal.Body>
            {form}
          </Modal.Body>
        </Modal>
      )
    }

    return (
      <Button onClick={this.onClick}>{this.props.title} {modal}</Button>
    )
  }

}
