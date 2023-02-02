package api


const (
	ResultCodeServerErr		   	= 11001

	ResultCodeExistAccount   	= 22001
	ResultCodeExistName 		= 22002
	ResultCodeIncorrectAccount  = 22003
	ResultCodeIncorrectPassword = 22004

	ResultCodeCorpExistCorpAccount   	= 23002
	ResultCodeCorpServerErr		   	= 23003
	ResultCodeCorpIncorrectAccount  = 22004
	ResultCodeCorpIncorrectPassword = 22005
	ResultCodeCorpNotActivate = 22006

	ResultCodePreviousPointErr = 41100

	ResultCodeUserKeyErr = 51001
	ResultCodeParamErr   = 51002

)