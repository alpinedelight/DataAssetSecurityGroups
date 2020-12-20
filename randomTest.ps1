function print_String{
   [cmdletbinding()]
   param(
      [Parameter(Mandatory=$false)][AllowEmptyString()][string] $name,
      [Parameter(Mandatory=$false)][boolean] $recurse = $false
   )
   Write-Output "Writing a single string"

   if($recurse){
      print_String -name $name -recurse $false
   }
   $name
}

print_String -name "" -recurse $true