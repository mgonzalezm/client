// @flow
import * as React from 'react'
import * as Kb from '../../../common-adapters'
import WalletEntry from '../../wallet-entry'
import type {Account} from '.'

type DropdownTextProps = {
  text: string,
}

/** A text selection, e.g., "Create a new account" */
export const DropdownText = ({text, ...props}: DropdownTextProps) => (
  <Kb.Box2 {...props} direction="horizontal" centerChildren={true} fullWidth={true}>
    <Kb.Text type="BodySemibold">{text}</Kb.Text>
  </Kb.Box2>
)

type SelectedEntryProps = {
  account: Account,
}

/** The display of the selected account in the dropdown */
export const SelectedEntry = ({account, ...props}: SelectedEntryProps) => (
  <Kb.Box2 {...props} direction="horizontal" centerChildren={true} gap="tiny">
    <Kb.Avatar size={32} username={account.user} />
    <Kb.Text type="Body">{account.name}</Kb.Text>
  </Kb.Box2>
)

type DropdownEntryProps = {
  account: Account,
}

export const DropdownEntry = (props: DropdownEntryProps) => (
  <WalletEntry
    keybaseUser={props.account.user}
    name={props.account.name}
    contents={props.account.contents}
    showWalletIcon={false}
  />
)
