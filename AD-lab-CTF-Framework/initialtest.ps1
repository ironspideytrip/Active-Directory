function Find-localadmins-wmi
{
 [CmdletBinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $ComputerName,
        [Parameter(ParameterSetName="Domain",Position = 1, Mandatory = $False)]
        [String]
        $Domain

    )
    Write-Output "Finding local-admins..."

    $groupMembers = get-wmiobject win32_groupUser -ComputerName $ComputerName -ErrorAction Stop
    $groupMembers = $groupMembers | where { $_.GroupComponent -like "*Administrators*"}
    foreach ($member in $groupMembers)
    {
        $name = $member.PartComponent.Split("=")
        $ugName = $name[2].Replace('"',"")
        if (($name[1]) -match $member.PSComputerName )
        {
        $ugName + " is Local Admin to machine"
         
        }
        else
        {
        $ugName
        }
     }

}
function Session-Machine
{
 [CmdletBinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $ComputerName
    )
    Invoke-Command -ComputerName $ComputerName  -ScriptBlock { quser }
    
}
function Misconfigure-ACL-Object
{
 [CmdletBinding()] Param(
        
        [Parameter(ParameterSetName="User",Position = 0, Mandatory = $False)]
        [String]
        $User,
        [Parameter(ParameterSetName="Group", Mandatory = $False)]
        [String]
        $Group,
        [Parameter(ParameterSetName="Misconfigure_object", Mandatory = $False)]
        [String]
        $Misconfigure_Object,
        [Parameter(ParameterSetName="Rights", Mandatory = $False)]
        [String]
        $Rights
     )  
     if($User)
     {
        $DistinguishedName=(Get-ADUser -Identity $User.Replace('"',"")).DistinguishedName
     }
     elseif($Group)
     {
     $DistinguishedName=(Get-ADGroup -Identity $Group).DistinguisedName
     }
     $loca="AD:\"+$DistinguishedName
     $acl=(Get-Acl $loca)
     $Useridentity=(Get-ADUser  -Identity steyngun)
     $sid = [System.Security.Principal.SecurityIdentifier] $Useridentity.SID
     $identity = [System.Security.Principal.IdentityReference] $SID
     $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
     $type = [System.Security.AccessControl.AccessControlType] "Allow"
     $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
     $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
     $acl.AddAccessRule($ace)
     Set-acl -aclobject $acl $loca
}
function Reset-Acl
{
[CmdletBinding()] Param(
        
        [Parameter(ParameterSetName="User",Position = 0, Mandatory = $False)]
        [String]
        $User,
        [Parameter(ParameterSetName="Group", Mandatory = $False)]
        [String]
        $Group
     )
     if($User)
     {
        $DistinguishedName=(Get-ADUser -Identity $User.Replace('"',"")).DistinguishedName
      }
    $loca="AD:\"+$DistinguishedName
    $acl=(Get-Acl $loca)
       
    foreach($acc in $acl.access ) 
    { 
    $value = $acc.IdentityReference.Value 
    if($value -match "steyngun") 
    { 
        $ACL.RemoveAccessRule($acc)
        Set-Acl -AclObject $acl $loca -ErrorAction Stop 
        
    } 

    }
}




