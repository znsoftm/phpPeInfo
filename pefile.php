<?
require_once(dirname(__FILE__)."/pedef.php");
class CPeFile
{

	var $file; // === false, if it's failed
	var $bPeFile; // if it's false, it means the file is not a pe file.
	var $DosHeader;
	var $NewSize;
	var $b32bit;
	var $NtHeader;
	var $FileHeader;
	var $OptionalHeader;
	var $bReady;
	var $SignatureDir;
	var $bSigned;
	var $fileLen;

	function __construct($pefile)
	{
		$this->bSigned=false;
		$this->bPeFile=false;
		$this->fileLen=0;

		$this->file=fopen($pefile,"r+b");
		if($this->file != false)
		{
			$this->fileLen=filesize($pefile);
			$tmp=fread($this->file,IMAGE_DOS_HEADER_LEN);
			if($tmp != false)
			{
				$this->DosHeader=unpack(IMAGE_DOS_HEADER,$tmp);
				if( $this->DosHeader["e_magic"] == IMAGE_DOS_SIGNATURE)
				{
					$this->bPeFile=true;

					fseek($this->file,$this->DosHeader["e_lfanew"],SEEK_SET);
					$tmp=fread($this->file,IMAGE_NT_HEADERS32_LEN);
					if($tmp != false)
					{
						$this->NtHeader = unpack(IMAGE_NT_HEADERS32,$tmp);
						if($this->NtHeader["Signature"] == IMAGE_NT_SIGNATURE)
						{
							$this->FileHeader = unpack(IMAGE_FILE_HEADER,$this->NtHeader["FileHeader"]);
							
							$this->bReady=true;
							switch($this->FileHeader["Machine"])
							{

								case IMAGE_FILE_MACHINE_I386:
										$this->b32bit=true;
									break;
								case IMAGE_FILE_MACHINE_AMD64:
								{
										fseek($this->file,$this->DosHeader["e_lfanew"],SEEK_SET);
										$tmp=fread($this->file,IMAGE_NT_HEADERS64_LEN);
										if($tmp != false)
										{
											$this->NtHeader = unpack(IMAGE_NT_HEADERS64,$tmp);
										}

										$this->b32bit=false;
								}
									break;
								default:
									$this->bReady=false;
							}

							if($this->bReady)
							{
//								var_dump($this->NtHeader);
								if($this->b32bit)
								{
									$this->OptionalHeader = unpack(IMAGE_OPTIONAL_HEADER32,$this->NtHeader["OptionalHeader"]);
								}
								else
									$this->OptionalHeader = unpack(IMAGE_OPTIONAL_HEADER64,$this->NtHeader["OptionalHeader"]);

								
								// get the signature directory , the no. 4 dir, offset 32, len 8

								$tmp=substr($this->OptionalHeader["DataDirectory"],32,8);
						
								$this->SignatureDir = unpack(IMAGE_DATA_DIRECTORY,$tmp);
								if($this->SignatureDir["VirtualAddress"] ==0)
								{
									$this->bSigned=false;
								}
								else
									$this->bSigned=true;



							//	var_dump($this->SignatureDir);

							}
							// get the option header from ntheader
							
						}

					}
				}
			//	var_dump($DosHeader);
			}
		}

	}

	function CheckIfSigned()
	{
		return $this->bSigned;

	}

	function ExtendFileSize($extraSize)
	{

		// ftruncate

		if( !$this->bPeFile ) //|| !this->bSigned)
			return false;

		if($this->bSigned) // modify signed directory to extend the file size
		{
			$this->OptionalHeader["CheckSum"]=0;
			$this->SignatureDir["Size"]+= GET_SIZE_PAGE($extraSize);
			$signedDir=pack(IMAGE_DATA_DIRECTORY_PACK,$this->SignatureDir["VirtualAddress"],$this->SignatureDir["Size"]); //construct a new dirdata for signed section.

			// for the whole datadirectory, it's 128 bytes, we need to replace it from no. 33,40 (indexes 32-39)
			$this->OptionalHeader["DataDirectory"]=substr($this->OptionalHeader["DataDirectory"],0,32).$signedDir.substr($this->OptionalHeader["DataDirectory"],40);
			// need to restore binary optionheader
			$opHeader=$this->OptionalHeader;
			if($this->b32bit)
			{
				$tmpOptionalHeader=pack(IMAGE_OPTIONAL_HEADER32_PACK,$opHeader["Magic"],$opHeader["MajorLinkerVersion"],$opHeader["MinorLinkerVersion"],$opHeader["SizeOfCode"],$opHeader["SizeOfInitializedData"],$opHeader["SizeOfUninitializedData"]
				,$opHeader["AddressOfEntryPoint"],$opHeader["BaseOfCode"],$opHeader["BaseOfData"],$opHeader["ImageBase"],$opHeader["SectionAlignment"]	
				,$opHeader["FileAlignment"],$opHeader["MajorOperatingSystemVersion"]	,$opHeader["MinorOperatingSystemVersion"]	,$opHeader["MajorImageVersion"]	,$opHeader["MinorImageVersion"]	
				,$opHeader["MajorSubsystemVersion"]	,$opHeader["MinorSubsystemVersion"]	,$opHeader["Win32VersionValue"]	,$opHeader["SizeOfImage"]	,$opHeader["SizeOfHeaders"]	,$opHeader["CheckSum"]	
				,$opHeader["Subsystem"]	,$opHeader["DllCharacteristics"]	,$opHeader["SizeOfStackReserve"]	,$opHeader["SizeOfStackCommit"]	,$opHeader["SizeOfHeapReserve"]	,$opHeader["SizeOfHeapCommit"]	
			,$opHeader["LoaderFlags"]	,$opHeader["NumberOfRvaAndSizes"]	,$opHeader["DataDirectory"]
				);
				$tmpNTHeader=pack(IMAGE_NT_HEADERS32_PACK,$this->NtHeader["Signature"],$this->NtHeader["FileHeader"],$tmpOptionalHeader);
			}
			else
			{
				//$tmpOptionalHeader=pack(IMAGE_OPTIONAL_HEADER64_PACK,);
				$tmpNTHeader=pack(IMAGE_NT_HEADERS64_PACK,$this->NtHeader["Signature"],$this->NtHeader["FileHeader"],$tmpOptionalHeader);
			}

			fseek($this->file,$this->DosHeader["e_lfanew"],SEEK_SET);
			$len=fwrite($this->file,$tmpNTHeader); // write new ntheder back to pe file
		}

		fseek($this->file,0,SEEK_END);
		ftruncate($this->file,$this->fileLen + GET_SIZE_PAGE($extraSize)); //extend the filesize of a given file

	}

	function GetFileVersion()
	{


	}

	//  bFromEnd, if it is set to true, the data will be write at the end of this pe file
	//
	//	$data need to be pack with function pack (binary format)
	//
	//
	function AppendData($data,$offset)
	{

		if(fseek($this->file,0-$offset,SEEK_END) !=0)
		{
			echo "error while appending data into this file";
			return false;
		}
			
		return fwrite($this->file,$data);

	}

	function GetOriginalSize()
	{
			return $this->fileLen;
	}

	function __destruct()
	{

		if($this->file != false)
		{
			fclose($this->file);
		}

	}




}


?>