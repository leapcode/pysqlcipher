import React from 'react'

import './layout.less'

class HorizontalLayout extends React.Component {
  static get defaultProps() {return{
    equalWidths: false
  }}

  constructor(props) {
    super(props)
  }

  render() {
    let className = "horizontal-layout"
    if (this.props.equalWidths) {
      className = className + " equal" + this.props.children.length
    }
    return (
      <div className={className}>
        {this.props.children}
      </div>
    )
  }
}

class Column extends React.Component {
  constructor(props) {
    super(props)
  }

  render() {
    return (
      <div className="layout-column">
        {this.props.children}
      </div>
    )
  }
}

export {HorizontalLayout, Column}