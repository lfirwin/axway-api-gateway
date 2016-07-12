

while read line
do
   if [[ $line == \#* ]] || [[ $line == '' ]]
   then
      continue
   else
      #echo $line
      envVar=(${line//=/ })
      #echo $envVar
      count=$(grep $envVar /Users/leland/Documents/Axway/stash/test/a93758d3-aa0d-41e3-82cb-80a97038cb3c/*.xml | wc -l)
      if [[ $count -eq 0 ]]
      then
         echo $envVar
      fi
   fi
done < <(cat /Users/leland/Documents/Axway/stash/vordelconfig/deploy/environments/hint3/envVariables.props)
