import bitmask from 'lib/bitmask'

const EVENTS = [
    "CLIENT_SESSION_ID",
    "CLIENT_UID",
    "RAISE_WINDOW",
    "UPDATER_DONE_UPDATING",
    "UPDATER_NEW_UPDATES",

    "KEYMANAGER_DONE_UPLOADING_KEYS",  // (address)
    "KEYMANAGER_FINISHED_KEY_GENERATION",  // (address)
    "KEYMANAGER_KEY_FOUND",  // (address)
    "KEYMANAGER_KEY_NOT_FOUND",  // (address)
    "KEYMANAGER_LOOKING_FOR_KEY",  // (address)
    "KEYMANAGER_STARTED_KEY_GENERATION",  // (address)

    "SOLEDAD_CREATING_KEYS",  // {uuid, userid}
    "SOLEDAD_DONE_CREATING_KEYS",  // {uuid, userid}
    "SOLEDAD_DONE_DATA_SYNC",  // {uuid, userid}
    "SOLEDAD_DONE_DOWNLOADING_KEYS",  // {uuid, userid}
    "SOLEDAD_DONE_UPLOADING_KEYS",  // {uuid, userid}
    "SOLEDAD_DOWNLOADING_KEYS",  // {uuid, userid}
    "SOLEDAD_INVALID_AUTH_TOKEN",  // {uuid, userid}
    "SOLEDAD_SYNC_RECEIVE_STATUS",  // {uuid, userid}
    "SOLEDAD_SYNC_SEND_STATUS",  // {uuid, userid}
    "SOLEDAD_UPLOADING_KEYS",  // {uuid, userid}
    "SOLEDAD_NEW_DATA_TO_SYNC",

    "MAIL_FETCHED_INCOMING",  // (userid)
    "MAIL_MSG_DECRYPTED",  // (userid)
    "MAIL_MSG_DELETED_INCOMING",  // (userid)
    "MAIL_MSG_PROCESSING",  // (userid)
    "MAIL_MSG_SAVED_LOCALLY",  // (userid)
    "MAIL_UNREAD_MESSAGES",  // (userid, number)

    "IMAP_SERVICE_STARTED",
    "IMAP_SERVICE_FAILED_TO_START",
    "IMAP_UNHANDLED_ERROR",
    "IMAP_CLIENT_LOGIN",  // (username)

    "SMTP_SERVICE_STARTED",
    "SMTP_SERVICE_FAILED_TO_START",
    "SMTP_START_ENCRYPT_AND_SIGN",  // (from_addr)
    "SMTP_END_ENCRYPT_AND_SIGN",  // (from_addr)
    "SMTP_START_SIGN",  // (from_addr)
    "SMTP_END_SIGN",  // (from_addr)
    "SMTP_SEND_MESSAGE_START",  // (from_addr)
    "SMTP_SEND_MESSAGE_SUCCESS",  // (from_addr)
    "SMTP_RECIPIENT_ACCEPTED_ENCRYPTED",  // (userid, dest)
    "SMTP_RECIPIENT_ACCEPTED_UNENCRYPTED",  // (userid, dest)
    "SMTP_CONNECTION_LOST",  // (userid, dest)
    "SMTP_RECIPIENT_REJECTED",  // (userid, dest)
    "SMTP_SEND_MESSAGE_ERROR"  // (userid, dest)
]


export default class EventLogger {
  constructor() {
    this.logEvent = this.logEvent.bind(this)
    for (let event of EVENTS) {
      console.log('register event ' + event)
      bitmask.events.register(event, this.logEvent)
    }
  }
  logEvent(event, msg) {
    console.log("EVENT: " + event, msg)
  }
}