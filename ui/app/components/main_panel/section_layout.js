//
// This is the layout for a service section in the main window.
// It does not do anything except for arrange items using css and html.
//

import React from 'react'
import { Button, Glyphicon } from 'react-bootstrap'

export default class SectionLayout extends React.Component {

  static get defaultProps() {return{
    icon: null,       // icon name
    buttons: null,    // button content
    status: null,     // must be one of: on, off, unknown, wait, disabled
    header: null,     // the first line content
    body: null,       // expanded content
    message: null,    // alert content
    onExpand: null,   // callback
    className: "",
    style: {}
  }}

  constructor(props) {
    super(props)
  }

  render() {
    let className = ["service-section", this.props.className].join(' ')
    let status = null
    let icon = null
    let buttons = null
    let expander = null
    let body = null

    if (this.props.onExpand) {
      let glyph = this.props.body ? 'triangle-top' : 'triangle-bottom'
      expander = (
        <div className="expander clickable" onClick={this.props.onExpand}>
          <Glyphicon glyph={glyph} />
        </div>
      )
    } else {
      expander = (
        <div className="expander" />
      )
    }
    if (this.props.status) {
      status = (
        <div className="status">
          <img src={'img/' + this.props.status + '.svg' } />
        </div>
      )
    }
    if (this.props.icon) {
      icon = (
        <div className="icon">
          <img src={'img/' + this.props.icon + '.svg'} />
        </div>
      )
    }
    if (this.props.buttons) {
      buttons = (
        <div className="buttons">
          {this.props.buttons}
        </div>
      )
    }
    if (this.props.body || this.props.message) {
      body = (
        <div className="body-row">
          {this.props.message}
          {this.props.body}
        </div>
      )
    }

    return(
      <div className={className} style={this.props.style}>
        {expander}
        <div className="shade">
          {icon}
          <div className="inner">
            <div className="header-row">
              <div className="header">
                {this.props.header}
              </div>
              {buttons}
            </div>
            {body}
          </div>
          {status}
        </div>
      </div>
    )
  }
}
