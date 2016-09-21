//
// A simple list of items, with minus and plus buttons to add and remove
// items.
//

import React from 'react'
import {Button, ButtonGroup, ButtonToolbar, Glyphicon, FormControl} from 'react-bootstrap'

import './list_editor.less'

class ListEdit extends React.Component {

  static get defaultProps() {return{
    width: null,
    items: [
      'aaaaaaa',
      'bbbbbbb',
      'ccccccc'
    ],
    selected: null,  // string of the selected item
    onRemove: null,
    onAdd: null,
    onSelect: null
  }}

  constructor(props) {
    super(props)
    this.click  = this.click.bind(this)
    this.add    = this.add.bind(this)
    this.remove = this.remove.bind(this)
  }

  row(str) {
    return this.props.items.indexOf(str)
  }

  click(e) {
    let row = parseInt(e.target.value)
    if (row >= 0) {
      if (this.props.onSelect) {
        this.props.onSelect(this.props.items[row])
      }
    }
  }

  add() {
    if (this.props.onAdd) {
      this.props.onAdd()
    }
  }

  remove() {
    if (this.props.onRemove) {
      let currentRow = this.row(this.props.selected)
      let newSelected = null
      if (this.props.items.length == currentRow + 1) {
        // if we remove the last item, set the new selected to be
        // the new last item.
        newSelected = this.props.items[currentRow - 1]
      } else {
        newSelected = this.props.items[currentRow + 1]
      }
      this.props.onRemove(this.props.selected, newSelected)
    }
  }

  render() {
    let options = null
    if (this.props.items) {
      options = this.props.items.map((item, i) => {
        return <option className="list-option" key={i} value={i}>{item}</option>
      }, this)
    }
    return(
      <div className="list-editor">
        <FormControl
          value={this.row(this.props.selected)}
          className="list-select"
          componentClass="select" size="5" onChange={this.click}>
          {options}
        </FormControl>
        <ButtonToolbar className="pull-right list-toolbar">
          <ButtonGroup>
            <Button onClick={this.add}>
              <Glyphicon glyph="plus" />
            </Button>
            <Button disabled={this.props.selected < 0} onClick={this.remove}>
              <Glyphicon glyph="minus" />
            </Button>
          </ButtonGroup>
        </ButtonToolbar>
      </div>
    )
  }

}

ListEdit.propTypes = {
  children: React.PropTypes.oneOfType([
    React.PropTypes.element,
    React.PropTypes.arrayOf(React.PropTypes.element)
  ])
}

export default ListEdit
