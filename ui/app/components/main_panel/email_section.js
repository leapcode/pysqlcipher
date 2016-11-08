import React from 'react'
import { Button, Glyphicon, Alert, ButtonToolbar } from 'react-bootstrap'

import SectionLayout from './section_layout'
import IMAPButton from './imap_button'

import Account from 'models/account'
import Spinner from 'components/spinner'
import bitmask from 'lib/bitmask'
import App from 'app'

const GENERAL_NOTICES = [
  "KEYMANAGER_KEY_FOUND",  // (address)
  "KEYMANAGER_KEY_NOT_FOUND",  // (address)
  "KEYMANAGER_LOOKING_FOR_KEY",  // (address)
  "KEYMANAGER_DONE_UPLOADING_KEYS",  // (address)

  "SMTP_START_ENCRYPT_AND_SIGN",  // (from_addr)
  "SMTP_END_ENCRYPT_AND_SIGN",  // (from_addr)
  "SMTP_START_SIGN",  // (from_addr)
  "SMTP_END_SIGN",  // (from_addr)
  "SMTP_SEND_MESSAGE_START",  // (from_addr)
  "SMTP_SEND_MESSAGE_SUCCESS"  // (from_addr)
]

const ACCOUNT_NOTICES = [
  "IMAP_CLIENT_LOGIN",  // (username)

  "MAIL_FETCHED_INCOMING",  // (userid)
  "MAIL_MSG_DECRYPTED",  // (userid)
  "MAIL_MSG_DELETED_INCOMING",  // (userid)
  "MAIL_MSG_PROCESSING",  // (userid)
  "MAIL_MSG_SAVED_LOCALLY",  // (userid)

  "SMTP_RECIPIENT_ACCEPTED_ENCRYPTED",  // (userid, dest)
  "SMTP_RECIPIENT_ACCEPTED_UNENCRYPTED",  // (userid, dest)
  "SMTP_RECIPIENT_REJECTED",  // (userid, dest)
  "SMTP_SEND_MESSAGE_ERROR"  // (userid, dest)
]

const STATUSES = [
  "KEYMANAGER_FINISHED_KEY_GENERATION",  // (address)
  "KEYMANAGER_STARTED_KEY_GENERATION",  // (address)
  "SMTP_SERVICE_STARTED",
  "MAIL_UNREAD_MESSAGES",  // (userid, number)
  "IMAP_SERVICE_STARTED"
]

const STATUS_ERRORS = [
  "IMAP_SERVICE_FAILED_TO_START",
  "IMAP_UNHANDLED_ERROR",
  "SMTP_SERVICE_FAILED_TO_START",
  "SMTP_CONNECTION_LOST",  // (userid, dest)
]

export default class EmailSection extends React.Component {

  static get defaultProps() {return{
    account: null
  }}

  constructor(props) {
    super(props)
    this.state = {
      status: 'unknown', // on, off, unknown, wait, disabled, error
      messages: [],
      expanded: true
    }
    this.expand    = this.expand.bind(this)
    this.openKeys = this.openKeys.bind(this)
    this.openApp   = this.openApp.bind(this)
    this.openPrefs = this.openPrefs.bind(this)
    this.logEvent  = this.logEvent.bind(this)
  }

  componentWillMount() {
    //let events = [].concat(GENERAL_NOTICES, ACCOUNT_NOTICES, STATUSES, STATUS_ERRORS)
    //for (let event of events) {
    //  bitmask.events.register(event, this.logEvent)
    //}
    bitmask.mail.status().then(status => {
      // either 'running' or 'disabled'
      let newstatus = 'error'
      if (status['mail'] == 'running') {
        newstatus = 'on'
      } else if (status['mail'] == 'disabled') {
        newstatus = 'disabled'
      }
      this.setState({status: newstatus})
    })
  }

  logEvent(event, msg) {
    console.log("EVENT: " + event, msg)
  }

  openKeys() {
    App.show('addressbook', {account: this.props.account})
  }

  openApp() {}

  openPrefs() {}

  expand() {
    this.setState({expanded: !this.state.expanded})
  }

  render () {
    //let message = null
    //if (this.state.error) {
    //  // style may be: success, warning, danger, info
    //  message = (
    //    <Alert bsStyle="danger">{this.state.error}</Alert>
    //  )
    //}
    let button = null
    let body = null
    let header = <h1>Mail</h1>
    if (this.state.status == 'on') {
      // button = <Button onClick={this.openKeys}>Addressbook</Button>
    }
    if (this.state.status == 'disabled') {
      header = <h1>Mail Disabled</h1>
    }
    if (this.state.expanded) {
      body = (
        <ButtonToolbar>
          <IMAPButton account={this.props.account} />
          <Button onClick={this.openKeys}>Addressbook</Button>
        </ButtonToolbar>
      )
    }
    return (
      <SectionLayout icon="envelope" status={this.state.status}
        onExpand={this.expand} buttons={button} header={header} body={body} />
    )
  }
}
