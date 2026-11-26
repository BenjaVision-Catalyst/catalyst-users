Class {
	#name : 'CUAuthenticatedQuicApplication',
	#superclass : 'CCQuicApplication',
	#instVars : [
		'sessions'
	],
	#category : 'BVC-Users-Connect-Core',
	#package : 'BVC-Users-Connect-Core'
}

{ #category : 'authentication' }
CUAuthenticatedQuicApplication >> authenticationOperation [
	^ self subclassResponsibility
]

{ #category : 'configuration' }
CUAuthenticatedQuicApplication >> configure: aConfiguration [
	super configure: aConfiguration.
	sessions := CUConnectUserSessions
			verifyingWith: [ :proof :connection | self verifiedUserForProof: proof connection: connection ]
]

{ #category : 'execution' }
CUAuthenticatedQuicApplication >> execute: aRequest asVerifiedUser: identity using: producer [
	^ self subclassResponsibility
]

{ #category : 'execution' }
CUAuthenticatedQuicApplication >> execute: aRequest using: producer [
	| connection identity reply |
	connection := aRequest connectionIdentifier.
	aRequest isSubscription ifTrue: [ ^ self replyWith: #[] status: 403 ].
	aRequest operation = self authenticationOperation
		ifTrue: [ identity := sessions authenticate: aRequest body forConnection: connection.
			reply := identity ifNil: [ ^ self replyWith: #[] status: 403 ].
			^ self replyWith: reply utf8Encoded status: 0 ].
	identity := sessions userIdentifierForConnection: connection.
	identity ifNil: [ ^ self replyWith: #[] status: 403 ].
	^ self
		execute: aRequest
		asVerifiedUser: identity
		using: producer
]

{ #category : 'execution' }
CUAuthenticatedQuicApplication >> replyWith: bytes status: status [
	| response |
	response := CCQuicDeferredResponse new.
	response complete: bytes status: status.
	^ response
]

{ #category : 'configuration' }
CUAuthenticatedQuicApplication >> requiresConnectionIdentity [
	^ true
]

{ #category : 'lifecycle' }
CUAuthenticatedQuicApplication >> reset [
	sessions ifNotNil: [ sessions reset ].
	super reset
]

{ #category : 'lifecycle' }
CUAuthenticatedQuicApplication >> retireConnection: connection [
	sessions retireConnection: connection
]

{ #category : 'authentication' }
CUAuthenticatedQuicApplication >> verifiedUserForProof: proof connection: connection [
	^ self subclassResponsibility
]
