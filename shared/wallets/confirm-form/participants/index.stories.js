// @flow
import * as React from 'react'
import * as Sb from '../../../stories/storybook'
import Participants from '.'

const provider = Sb.createPropProviderWithCommon()

const defaultProps = {
  yourUsername: 'cjb',
  fromAccountName: 'Primary Account',
  fromAccountContents: '2000 XLM',

  recipientUsername: 'yen',
  recipientFullName: 'Addie Stokes',

  recipientStellarAddress: 'GBQTE2V7Y356TFBZL6YZ2PA3KIILNSAAQRV5C7MVWS22KQTS4EMK7I4',

  recipientAccountName: 'Secondary Account',
  recipientAccountContents: '123 XLM',
}

const load = () => {
  Sb.storiesOf('Wallets/SendForm/Participants', module)
    .addDecorator(provider)
    .add('To Keybase user', () => <Participants {...defaultProps} recipientType="keybaseUser" />)
    .add('To other account', () => <Participants {...defaultProps} recipientType="otherAccount" />)
    .add('To stellar address', () => <Participants {...defaultProps} recipientType="stellarPublicKey" />)
}

export default load
