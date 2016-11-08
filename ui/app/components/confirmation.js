//
// A simple diagon that asks if you are sure.
//

import React from 'react'
import {Button, ButtonGroup, ButtonToolbar, Glyphicon, Modal}
  from 'react-bootstrap'

export default class Confirmation extends React.Component {

  static get defaultProps() {return{
    title: "Are you sure?",
    onCancel: null,
    onAccept: null,
    acceptStr: 'Accept',
    cancelStr: 'Cancel'
  }}

  constructor(props) {
    super(props)
  }

  render() {
    return (
      <Modal show={true} onHide={this.props.onCancel}>
        <Modal.Header closeButton>
          <Modal.Title>{this.props.title}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <ButtonToolbar>
            <Button onClick={this.props.onAccept} bsStyle="success">
              {this.props.acceptStr}
            </Button>
            <Button onClick={this.props.onCancel}>
              {this.props.cancelStr}
            </Button>
          </ButtonToolbar>
        </Modal.Body>
      </Modal>
    )
  }
}

