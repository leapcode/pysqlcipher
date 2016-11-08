import React from 'react'

import './layout.less'

class HorizontalLayout extends React.Component {
  static get defaultProps() {return{
    equalWidths: false,
    className: ''
  }}

  constructor(props) {
    super(props)
  }

  render() {
    let className = "horizontal-layout " + this.props.className
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
  static get defaultProps() {return{
    className: ''
  }}

  constructor(props) {
    super(props)
  }

  render() {
    let className = "layout-column " + this.props.className
    return (
      <div className={className}>
        {this.props.children}
      </div>
    )
  }
}

class VerticalLayout extends React.Component {
  static get defaultProps() {return{
    equalWidths: false,
    className: ''
  }}

  constructor(props) {
    super(props)
  }

  render() {
    let className = "vertical-layout " + this.props.className
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

class Row extends React.Component {
  static get defaultProps() {return{
    className: '',
    size: 'expand',
    gutter: ''
  }}

  constructor(props) {
    super(props)
  }

  render() {
    let style = {}
    if (this.props.gutter) {
      style = {marginBottom: this.props.gutter}
    }
    let className = ["layout-row", this.props.className, this.props.size].join(" ")
    return (
      <div style={style} className={className}>
        {this.props.children}
      </div>
    )
  }
}

export {HorizontalLayout, VerticalLayout, Column, Row}