import {
  createAgent,
  CredentialPayload,
  ICredentialPlugin,
  IDIDManager,
  IIdentifier,
  IKeyManager,
  IResolver,
  TAgent,
} from '../../../core/src'
import { CredentialPlugin } from '../../../credential-w3c/src'
import { DIDManager, MemoryDIDStore } from '../../../did-manager/src'
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '../../../key-manager/src'
import { KeyManagementSystem } from '../../../kms-local/src'
import { getDidKeyResolver, KeyDIDProvider } from '../../../did-provider-key/src'
import { DIDResolverPlugin } from '../../../did-resolver/src'
import { ContextDoc } from '../types'
import { CredentialIssuerLD } from '../action-handler'
import { LdDefaultContexts } from '../ld-default-contexts'
import { VeramoEd25519Signature2020 } from '../suites/Ed25519Signature2020'
import { Resolver } from 'did-resolver'

jest.setTimeout(300000)

const customContext: Record<string, ContextDoc> = {
  'custom:example.context': {
    '@context': {
      nothing: 'custom:example.context#blank',
    },
  },
}

describe('credential-LD full flow', () => {
  let didKeyIdentifier: IIdentifier
  let agent: TAgent<IResolver & IKeyManager & IDIDManager & ICredentialPlugin>

  beforeAll(async () => {
    agent = createAgent({
      plugins: [
        new KeyManager({
          store: new MemoryKeyStore(),
          kms: {
            local: new KeyManagementSystem(new MemoryPrivateKeyStore()),
          },
        }),
        new DIDManager({
          providers: {
            'did:key': new KeyDIDProvider({ defaultKms: 'local' }),
          },
          store: new MemoryDIDStore(),
          defaultProvider: 'did:key',
        }),
        new DIDResolverPlugin({
          resolver: new Resolver({
            ...getDidKeyResolver(),
          }),
        }),
        new CredentialPlugin(),
        new CredentialIssuerLD({
          contextMaps: [LdDefaultContexts, customContext],
          suites: [new VeramoEd25519Signature2020()],
        }),
      ],
    })
    didKeyIdentifier = await agent.didManagerCreate()
  })

  it('works with Ed25519Signature2020 credential', async () => {
    const credential: CredentialPayload = {
      issuer: didKeyIdentifier.did,
      '@context': ['custom:example.context'],
      credentialSubject: {
        nothing: 'else matters',
      },
    }
    const verifiableCredential = await agent.createVerifiableCredential({
      credential,
      proofFormat: 'lds',
    })

    expect(verifiableCredential).toBeDefined()

    const result = await agent.verifyCredential({
      credential: verifiableCredential,
    })

    expect(result.verified).toBe(true)
  })

  it('works with Ed25519Signature2020 credential and presentation', async () => {
    const credential: CredentialPayload = {
      issuer: didKeyIdentifier.did,
      '@context': ['custom:example.context'],
      credentialSubject: {
        nothing: 'else matters',
      },
    }
    const verifiableCredential1 = await agent.createVerifiableCredential({
      credential,
      proofFormat: 'lds',
    })

    const verifiablePresentation = await agent.createVerifiablePresentation({
      presentation: {
        verifiableCredential: [verifiableCredential1],
        holder: didKeyIdentifier.did,
      },
      challenge: 'VERAMO',
      proofFormat: 'lds',
    })

    expect(verifiablePresentation).toBeDefined()

    const result = await agent.verifyPresentation({
      presentation: verifiablePresentation,
      challenge: 'VERAMO',
    })

    expect(result.verified).toBe(true)
  })
})
