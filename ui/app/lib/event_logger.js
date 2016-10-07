import bitmask from 'lib/bitmask'

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

export default class EventLogger {
  constructor() {
    this.logEvent = this.logEvent.bind(this)
    let events = [].concat(GENERAL_NOTICES, ACCOUNT_NOTICES, STATUSES, STATUS_ERRORS)
    for (let event of events) {
      console.log('register event ' + event)
      bitmask.events.register(event, this.logEvent)
    }
  }
  logEvent(event, msg) {
    console.log("EVENT: " + event, msg)
  }
}