//
// Interface to the key manager
//


import React from 'react'
import App from 'app'
import { ButtonToolbar, Button, Glyphicon, Alert } from 'react-bootstrap'

import {VerticalLayout, Row} from 'components/layout'
import bitmask from 'lib/bitmask'
import './addressbook.less'

export default class Addressbook extends React.Component {

  static get defaultProps() {return{
    account: null
  }}

  constructor(props) {
    super(props)
    this.state = {
      keys: null,
      errorMsg: ""
    }
    this.close = this.close.bind(this)
  }

  componentWillMount() {
    bitmask.keys.list(true).then(keys => {
      this.setState({keys: keys})
    }, error => {
      this.setState({errorMsg: error})
    })
  }

  close() {
    App.show('main', {initialAccount: this.props.account})
  }

  render() {
    let alert = null
    let keyList = null

    if (this.state.errorMsg) {
      alert = (
        <Alert bsStyle="danger">{this.state.errorMsg}</Alert>
      )
    }

    keyList = <b>list of keys goes here</b>

    let buttons = (
      <Button onClick={this.close} className="btn-inverse">
        <Glyphicon glyph="remove" />&nbsp;
        Close
      </Button>
    )

    let page = (
      <VerticalLayout className="darkBg">
        <Row className="header" size="shrink" gutter="8px">
          <div className="pull-right">
            {buttons}
          </div>
          <div className="title">
            {this.props.account.address}
            <h1>Addressbook</h1>
          </div>
        </Row>
        <Row className="lightFg" size="expand">
          {alert}
          {keyList}
        </Row>
      </VerticalLayout>
    )
    return page
  }

}
