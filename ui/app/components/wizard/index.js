//
// The provider setup wizard
//

import React from 'react'
import App from 'app'

import ProviderSelectStage from './provider_select_stage'
import RegisterStage from './register_stage'
import './wizard.less'

export default class Wizard extends React.Component {

  static get defaultProps() {return{
    stage: "provider"
  }}

  constructor(props) {
    super(props)
  }

  render() {
    let stage = null
    switch(this.props.stage) {
      case 'provider':
        stage = <ProviderSelectStage {...this.props}/>
        break
      case 'register':
        stage = <RegisterStage {...this.props}/>
        break
    }
    return(
      <div className="wizard">
        {stage}
      </div>
    )
  }

}
