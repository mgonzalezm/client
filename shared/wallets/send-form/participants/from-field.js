// @flow
import * as React from 'react'
import * as Kb from '../../../common-adapters'
import Row from '../../participants-row'
import {SelectedEntry, DropdownEntry} from './dropdown'
import type {Account} from '.'

type FromFieldProps = {|
  initialAccount: Account,
  accounts: Account[],
|}

type FromFieldState = {|
  selectedAccount: Account,
|}

class FromField extends React.Component<FromFieldProps, FromFieldState> {
  state = {
    selectedAccount: this.props.initialAccount,
  }

  _onDropdownChange = (node: React.Node) => {
    if (React.isValidElement(node)) {
      console.log(node)
    }
  }

  render() {
    const items = this.props.accounts.map((account, index) => <DropdownEntry key={index} account={account} />)

    return (
      <Row heading="From:" headingAlignment="Right">
        <Kb.Dropdown
          onChanged={this._onDropdownChange}
          items={items}
          selected={<SelectedEntry account={this.state.selectedAccount} />}
        />
      </Row>
    )
  }
}

export default FromField
