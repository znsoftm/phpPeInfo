<?
require_once(dirname(__FILE__)."/pefile.php");

// some definitons for packing setup files.

/*
#define QM_NAME_LEN 64
#define QM_MD5_LEN_EX 33

#define QM_RES_NAME _T("QMCFG")

#define QM_SETUP_FLAG  'QMDP'
#define QM_MAX_STR_LEN 260
#pragma pack(1)
typedef struct
{
	ULONG			  nNumCfg;			//总数值配项数
	ULONG			  nStrCfg;			//总字符串配置项数
	ULONG			  nFile;			// the amount of extra files
	ULONG			  nCert;			//证书个数
}QM_SETUP_META;

typedef enum _cert_type
{
	QCT_ROOT = 1,
	QCT_SUB  = 2,
	QCT_PFX  = 3,

}QM_SP_CERT_TYPE;

typedef struct 
{
	QM_SP_CERT_TYPE	nType;	//证书类型
	ULONG			FileSize;     // 文件大小

}QM_RES_CERT,*PQM_RES_CERT;

typedef struct
{
	ULONG			FileSize; // 文件大小
	char			szDstPath[QM_MAX_STR_LEN]; // {app}, {common file}

}QM_RES_FILE, *PQM_RES_FILE;

typedef struct
{
	char			szName[QM_NAME_LEN];
	ULONG			nValue; // 4 bytes
}QM_RES_NUM_CFG;

typedef struct
{
	char			szName[QM_NAME_LEN];   //64 bytes
	char			szValue[QM_MAX_STR_LEN]; // MAX_PATH, 260bytes
}QM_RES_STR_CFG;

typedef struct  
{
 ULONG				ulFlag;
 ULONG				nTotalSize;
 QM_SETUP_META      MetaTable;
 }QM_SETUP_MAGIC_HEADER;
 */
define("QM_NAME_LEN", 64);
define("QM_RES_NAME","QMCFG");

define("QM_SETUP_FLAG",'PDMQ');
define("QM_MAX_STR_LEN",260);

define("QM_SETUP_META","LLLL");
define("QM_SETUP_META_LEN",16);
define("QM_RES_CERT","LL");
define("QM_RES_FILE","La".QM_MAX_STR_LEN);
define("QM_RES_NUM_CFG","a".QM_NAME_LEN."L");
define("QM_RES_STR_CFG","a".QM_NAME_LEN."a".QM_MAX_STR_LEN);
define("QM_SETUP_MAGIC_HEADER","a4La".QM_SETUP_META_LEN); // a16 = length of meta table
define("QM_SETUP_MAGIC_HEADER_LEN",24);
define("QM_RES_CERT_LEN", 8);
define("QM_RES_FILE_LEN",264);
define("QM_RES_NUM_CFG_LEN",68);
define("QM_RES_STR_CFG_LEN",324);

define("QM_SPACE_LEN","L");




// file struct of setup config.
// header
// strcfg
// intcfg
// certitem
// fileitem


// Note:
//  the file to be contained in a pe file can't be a compressed file, such as .zip, .rar and so on.
//
class CPkgSetup extends CPeFile
{
	
	var $strCfg;
	var $intCfg;
	var $rootca;
	var $subca;
	var $files;
	function __construct($srcsetup,$params,$rootca,$subca,$files)
	{

		if( !is_array($params) || !is_array($params) || !is_array($subca) || !is_array($files))
		{
			die(" invalid parameters!");
		}
		parent::__construct($srcsetup);

		$this->rootca =$rootca;
		$this->subca = $subca;
		$this->files = $files;

		foreach ($params as $key => $val)
		{
			if(intval($val) === $val ) // number
			 $this->intCfg[$key]=$val;
			 else
			 $this->strCfg[$key]=$val;

		}

	
	}

	function __destruct()
	{


	}


	function PackIt()
	{
		$totalsize=QM_SETUP_MAGIC_HEADER_LEN+ QM_RES_CERT_LEN*(count($this->rootca) + count($this->subca)) + count($this->strCfg) *QM_RES_STR_CFG_LEN + count($this->intCfg) *QM_RES_NUM_CFG_LEN + count($this->files) *QM_RES_FILE_LEN;

// get the filesize of all files.
		foreach( $this->rootca as $key => $val)
		{
			$totalsize+=filesize( $val);

		}

		foreach( $this->subca as $key => $val)
		{
			$totalsize+=filesize( $val);

		}

		foreach( $this->files as $key => $val)
		{
			$totalsize+=filesize( $key);

		}
		
		$meta=pack(QM_SETUP_META,count($this->intCfg),count($this->strCfg),count($this->files), count($this->rootca)+count($this->subca));
		$magicHeader=pack(QM_SETUP_MAGIC_HEADER,QM_SETUP_FLAG,$totalsize,$meta); // pack magic_header

		$AllData=$magicHeader;
	// strcfg
		foreach($this->strCfg as $key =>$val)
		{
			$data=pack(QM_RES_STR_CFG,$key,$val);
			$AllData.=$data;
		}

	// num cfg
		foreach($this->intCfg as $key =>$val)
		{
			$data=pack(QM_RES_NUM_CFG,$key,$val);
			$AllData.=$data;
		}
	
	// root ca
		foreach($this->rootca as $key => $val)
		{
			if(file_exists($val))
			{
				$data=pack(QM_RES_CERT, 1,filesize($val));
				$AllData.=$data;
				$fc=file_get_contents($val);
				$AllData.=$fc;
			}
			
		}	

	  // sub ca
		foreach($this->subca as $key => $val)
		{
			if(file_exists($val))
			{
				$data=pack(QM_RES_CERT, 2,filesize($val));
				$AllData.=$data;
				$fc=file_get_contents($val);
				$AllData.=$fc;
			}
			
		}

	// customed files
		foreach($this->files as $key => $val)
		{
			if(file_exists($key))
			{
				$data=pack(QM_RES_FILE, filesize($key),$val);
				$AllData.=$data;
				$fc=file_get_contents($key);
				$AllData.=$fc;
			}
			
		}

		parent::ExtendFileSize($totalsize+4); // 4 refers to sizeof(ulong)

		/*
		echo GET_SIZE_PAGE($totalsize + 4);
		echo "\r\n";
		echo $totalsize;
		echo "\r\n";
		echo strlen($AllData);
		*/
		$offset=GET_SIZE_PAGE($totalsize + 4);
		parent::AppendData($AllData,$offset);


		$spacelen=pack(QM_SPACE_LEN,GET_SIZE_PAGE($totalsize + 4));
		parent::AppendData($spacelen,4);


	}


}


?>