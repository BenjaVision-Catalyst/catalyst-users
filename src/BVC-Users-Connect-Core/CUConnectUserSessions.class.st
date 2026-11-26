Class {
	#name : 'CUConnectUserSessions',
	#superclass : 'Object',
	#instVars : [
		'usersByConnection',
		'verifier'
	],
	#category : 'BVC-Users-Connect-Core',
	#package : 'BVC-Users-Connect-Core'
}

{ #category : 'instance creation' }
CUConnectUserSessions class >> verifyingWith: aBlock [
	^ self new verifier: aBlock
]

{ #category : 'authentication' }
CUConnectUserSessions >> authenticate: aProof forConnection: aConnectionIdentifier [
	| user identifier |
	(aConnectionIdentifier isInteger and: [ aConnectionIdentifier > 0 ])
		ifFalse: [ ^ nil ].
	(usersByConnection includesKey: aConnectionIdentifier) ifTrue: [ ^ nil ].
	usersByConnection size >= 64 ifTrue: [ ^ nil ].
	verifier ifNil: [ ^ nil ].
	user := verifier value: aProof value: aConnectionIdentifier.
	(user isKindOf: CUUser) ifFalse: [ ^ nil ].
	identifier := user userIdentifier.
	(identifier isString and: [ identifier isNotEmpty ]) ifFalse: [ ^ nil ].
	usersByConnection at: aConnectionIdentifier put: identifier copy.
	^ identifier copy
]

{ #category : 'initialization' }
CUConnectUserSessions >> initialize [
	super initialize.
	usersByConnection := Dictionary new
]

{ #category : 'lifecycle' }
CUConnectUserSessions >> reset [
	usersByConnection removeAll
]

{ #category : 'lifecycle' }
CUConnectUserSessions >> retireConnection: aConnectionIdentifier [
	usersByConnection removeKey: aConnectionIdentifier ifAbsent: [  ]
]

{ #category : 'authentication' }
CUConnectUserSessions >> userIdentifierForConnection: aConnectionIdentifier [
	^ (usersByConnection at: aConnectionIdentifier ifAbsent: [ ^ nil ]) copy
]

{ #category : 'initialization' }
CUConnectUserSessions >> verifier: aBlock [
	verifier ifNotNil: [ self error: 'Cannot replace the active Users verifier' ].
	verifier := aBlock.
	^ self
]
