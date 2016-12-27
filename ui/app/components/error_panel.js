import React from 'react'
import Center from './center'
import Area from './area'

export default class ErrorPanel extends React.Component {

  constructor(props) {
    super(props)
  }

  render () {
    var error_msg = null
    var error = this.props.error
    console.log(error)
    if (error instanceof Error && error.stack) {
      error_msg = error.stack
    } else if (error instanceof PromiseRejectionEvent) {
      error_msg = "Error connecting to bitmaskd"
    } else {
      error_msg = error.toString()
    }
    return (
      <Center width="600">
        <Area>
          <h1>Error</h1>
          {error_msg}
        </Area>
      </Center>
    )
  }
}
