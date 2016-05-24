var program = require('commander');
var xml2js = require('xml2js');
var parser = new xml2js.Parser();
var fs = require('fs');

program
  .version('0.0.1')
  .option('-a, --path1 [path]', 'Path to first item to compare')
  .option('-b, --path2 [path]', 'Path to second item to compare')
  .option('-c, --file1 [path]', 'Path to first item to compare')
  .option('-d, --file2 [path]', 'Path to second item to compare')
  .option('-r, --report', 'Report all permissions for options specified in -a or -c')
  .option('-s, --same', 'Also report the permissions that are the same')
  .parse(process.argv);

if(!program.report && (program.path1 || program.path2)){
  if (!program.path1) {
    console.log('Need to pass path1!');
    throw error;
  }
  if (!program.path2){
    console.log('Need to pass path2!');
    throw error;
  }

  fs.readdirSync(program.path1).forEach(function (file, index){
    console.log(file);
    try{
      var Sequence = exports.Sequence || require('sequence').Sequence
      var sequence = Sequence.create()
      sequence
        .then(function(next){
          parser.parseString(fs.readFileSync(program.path1 + '\\' + file), function (err, result) {
            next(err,result);
          })
        })
        .then(function(next,err,result1){
          parser.parseString(fs.readFileSync(program.path2 + '\\' + file), function (err, result) {
            next(err,result1,result);
          })
        })
        .then(function(next,err,profile1,profile2){
          if(profile1.Profile && profile2.Profile){
            compareProfiles(file, profile1.Profile, profile2.Profile);
          } else {
            if(profile1.PermissionSet && profile2.PermissionSet){
              compareProfiles(file, profile1.PermissionSet, profile2.PermissionSet);
            } else {
              console.log('ERROR: No profile or permission set found!')
            }
          }
        });
    }
    catch (e) {
      console.log(e);
    }
  });
}

if (program.report && (!program.path1 && !program.file1)){
  console.log('Need to pass path1 or file1');
  throw error;
}

if(program.report && program.path1){
  fs.readdirSync(program.path1).forEach(function (file, index){
    console.log(file);
    try{
      var Sequence = exports.Sequence || require('sequence').Sequence
      var sequence = Sequence.create()
      sequence
        .then(function(next){
          parser.parseString(fs.readFileSync(program.path1 + '\\' + file), function (err, result) {
            next(err,result);
          })
        })
        .then(function(next,err,profile1,profile2){
          if(profile1.Profile){
            compareProfiles(file, profile1.Profile, profile1.Profile);
          } else {
            if(profile1.PermissionSet && profile1.PermissionSet){
              compareProfiles(file, profile1.PermissionSet, profile1.PermissionSet);
            } else {
              console.log('ERROR: No profile or permission set found!')
            }
          }
        });
    }
    catch (e) {
      console.log(e);
    }
  });
}

if(!program.report && (program.file1 || program.file2)){
  if(!program.file1){
    console.log('Need to pass file 1!');
    throw error;
  }
  if(!program.file2){
    console.log('Need to pass file 2!');
    throw error;
  }
  var Sequence = exports.Sequence || require('sequence').Sequence
  var sequence = Sequence.create()
  sequence
    .then(function(next){
      parser.parseString(fs.readFileSync(program.file1, 'utf-8'), function (err, result) {
        next(err,result);
      })
    })
    .then(function(next,err,result1){
      parser.parseString(fs.readFileSync(program.file2, 'utf-8'), function (err, result) {
        next(err,result1,result);
      })
    })
    .then(function(next,err,profile1,profile2){
      compareProfiles("file", profile1.Profile, profile2.Profile);
    });
}

if(program.report && program.file1){
  var Sequence = exports.Sequence || require('sequence').Sequence
  var sequence = Sequence.create()
  sequence
    .then(function(next){
      parser.parseString(fs.readFileSync(program.file1, 'utf-8'), function (err, result) {
        next(err,result);
      })
    })
    .then(function(next,err,profile1,profile2){
      compareProfiles("file", profile1.Profile, profile1.Profile);
    });
}

function compareProfiles(file, SM, NISM){
  var fileName = file + ' - compare.csv';
  fs.writeFileSync(fileName, "Type,MetaData,Permission,Before,After\n");
  compareApplicationVisibilities(fileName, SM.applicationVisibilities, NISM.applicationVisibilities);
  compareClassAccesses(fileName, SM.classAccesses, NISM.classAccesses);
  compareCustom(fileName, SM.custom, NISM.custom);
  compareFieldPermissions(fileName, SM.fieldPermissions, NISM.fieldPermissions);
  compareObjectPermissions(fileName, SM.objectPermissions, NISM.objectPermissions);
  comparePageAccesses(fileName, SM.pageAccesses, NISM.pageAccesses);
  compareTabVisibilties(fileName, SM.tabVisibilities, NISM.tabVisibilities);
  compareUserLicense(fileName, SM.userLicense, NISM.userLicense);
  compareUserPermissions(fileName, SM.userPermissions, NISM.userPermissions);
  console.log(fileName);
}

/*
- application
- default
- visible*/
function compareApplicationVisibilities(f, p1, p2){
  if(p1 === p2 && !program.report){
    return false;
  }
  var p1Ctr = 0;
  var p2Ctr = 0;
  while(p1Ctr < p1.length && p2Ctr < p2.length){
    switch (true){
      case p1[p1Ctr].application[0] < p2[p2Ctr].application[0]:
        if(p1[p1Ctr].default){
          fs.appendFileSync(f,"Application Visibilities," + p1[p1Ctr].application[0] + ',Default, ' + p1[p1Ctr].default[0] + ',' + '\n');;
        }
        fs.appendFileSync(f,"Application Visibilities," + p1[p1Ctr].application[0] + ',Visible, ' + p1[p1Ctr].visible[0] + ',' + '\n');;
        p1Ctr++;
        break;
      case p1[p1Ctr].application[0] > p2[p2Ctr].application[0]:
        if(p2[p2Ctr].default){
          fs.appendFileSync(f,"Application Visibilities," + p2[p2Ctr].application[0] + ',Default,,' + p2[p2Ctr].default[0] + '\n');;
        }
        fs.appendFileSync(f,"Application Visibilities," + p2[p2Ctr].application[0] + ',Visible,,' + p2[p2Ctr].visible[0] + '\n');;
        p2Ctr++;
        break;
      case program.report:
        if(p1[p1Ctr].default){
          fs.appendFileSync(f,"Application Visibilities," + p1[p1Ctr].application[0] + ',Default, ' + p1[p1Ctr].default[0] + '\n');;
        }
        fs.appendFileSync(f,"Application Visibilities," + p1[p1Ctr].application[0] + ',Visible, ' + p1[p1Ctr].visible[0] + '\n');;
        p1Ctr++;
        p2Ctr++;
        break;
      default:
        if(p1[p1Ctr].default && p2[p2Ctr].default && (program.same || p1[p1Ctr].default[0] !== p2[p2Ctr].default[0])){
          fs.appendFileSync(f,"Application Visibilities," + p1[p1Ctr].application[0] + ',Default,' + p1[p1Ctr].default[0] + ',' + p2[p2Ctr].default[0] + '\n');
        }
        if(program.same || p1[p1Ctr].visible[0] !== p2[p2Ctr].visible[0]){
          fs.appendFileSync(f,"Application Visibilities," + p1[p1Ctr].application[0] + ',Visibile,' + p1[p1Ctr].visible[0] + ',' + p2[p2Ctr].visible[0] + '\n');
        }
        p1Ctr++;
        p2Ctr++;
    }
  }

  return true;
}

/*
- apexClass
- enabled*/
function compareClassAccesses(f, p1, p2){
  if(p1 === p2 && !program.report){
    return false;
  }
  var p1Ctr = 0;
  var p2Ctr = 0;
  while(p1Ctr < p1.length && p2Ctr < p2.length){
    switch (true){
      case p1[p1Ctr].apexClass[0] < p2[p2Ctr].apexClass[0]:
        fs.appendFileSync(f,"Class Accesses," + p1[p1Ctr].apexClass[0] + ',Enabled,' + p1[p1Ctr].enabled[0] + ',' + '\n');;
        p1Ctr++;
        break;
      case p1[p1Ctr].apexClass[0] > p2[p2Ctr].apexClass[0]:
        fs.appendFileSync(f,"Class Accesses," + p2[p2Ctr].apexClass[0] + ',Enabled,,' + p2[p2Ctr].enabled[0] + '\n');;
        p2Ctr++;
        break;
      case program.report:
        fs.appendFileSync(f,"Class Accesses," + p1[p1Ctr].apexClass[0] + ',Enabled,' + p1[p1Ctr].enabled[0] + '\n');;
        p1Ctr++;
        p2Ctr++;
        break;
      default:
        if(program.same || p1[p1Ctr].enabled[0] !== p2[p2Ctr].enabled[0]){
          fs.appendFileSync(f,"Class Accesses," + p1[p1Ctr].apexClass[0] + ',Enabled,' + p1[p1Ctr].enabled[0] + ',' + p2[p2Ctr].enabled[0] + '\n');
        }
        p1Ctr++;
        p2Ctr++;
    }
  }

  return true;
}

function compareCustom(f, p1, p2){
  if(p1 === p2 && !program.report){
    return false;
  }
  if(p1 && p2 && (program.same || p1[0] !== p2[0])){
    fs.appendFileSync(f,'Custom,,,' + p1[0] + ',' + p2[0] + '\n');
  }
  if(program.report){
    fs.appendFileSync(f,'Custom,,,' + p1[0] + '\n');
  }
  return true;
}


/*
- field
- readable
- editable*/
function compareFieldPermissions(f, p1, p2){
  if(p1 === p2 && !program.report){
    return false;
  }
  var p1Ctr = 0;
  var p2Ctr = 0;
  while(p1Ctr < p1.length && p2Ctr < p2.length){
    switch (true){
      case p1[p1Ctr].field[0] < p2[p2Ctr].field[0]:
        fs.appendFileSync(f,"Field Permissions," + p1[p1Ctr].field[0] + ',Readable,' + p1[p1Ctr].readable[0] + ',' + '\n');;
        fs.appendFileSync(f,"Field Permissions," + p1[p1Ctr].field[0] + ',Editable,' + p1[p1Ctr].editable[0] + ',' + '\n');;
        p1Ctr++;
        break;
      case p1[p1Ctr].field[0] > p2[p2Ctr].field[0]:
        fs.appendFileSync(f,"Field Permissions," + p2[p2Ctr].field[0] + ',Readable,,' + p2[p2Ctr].readable[0] + '\n');;
        fs.appendFileSync(f,"Field Permissions," + p2[p2Ctr].field[0] + ',Editable,,' + p2[p2Ctr].editable[0] + '\n');;
        p2Ctr++;
        break;
      case program.report:
        fs.appendFileSync(f,"Field Permissions," + p1[p1Ctr].field[0] + ',Readable,' + p1[p1Ctr].readable[0] + '\n');;
        fs.appendFileSync(f,"Field Permissions," + p1[p1Ctr].field[0] + ',Editable,' + p1[p1Ctr].editable[0] + '\n');;
        p1Ctr++;
        p2Ctr++;
        break;
      default:
        if(program.same || p1[p1Ctr].readable[0] !== p2[p2Ctr].readable[0]){
          fs.appendFileSync(f,"Field Permissions," + p1[p1Ctr].field[0] + ',Readable,' + p1[p1Ctr].readable[0] + ',' + p2[p2Ctr].readable[0] + '\n');
        }
        if(program.same || p1[p1Ctr].editable[0] !== p2[p2Ctr].editable[0]){
          fs.appendFileSync(f,"Field Permissions," + p1[p1Ctr].field[0] + ',Editable,' + p1[p1Ctr].editable[0] + ',' + p2[p2Ctr].editable[0] + '\n');
        }
        p1Ctr++;
        p2Ctr++;
    }
  }

  return true;
}

/*
- layout (op?)
- recordType*/
function compareLayoutAssignments(f, p1, p2){
  if(p1 === p2 && !program.report){
    return false;
  }

  return true;
}

/*
- object
- allowCreate
- allowDelete
- allowEdit
- allowRead
- modifyAllRecords
- viewAllRecords*/
function compareObjectPermissions(f, p1, p2){
  if(p1 === p2 && !program.report){
    return false;
  }
  var p1Ctr = 0;
  var p2Ctr = 0;
  while(p1Ctr < p1.length && p2Ctr < p2.length){
    switch (true){
      case p1[p1Ctr].object[0] < p2[p2Ctr].object[0]:
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowCreate,' + p1[p1Ctr].allowCreate[0] + ',' + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowDelete,' + p1[p1Ctr].allowDelete[0] + ',' + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowEdit,' + p1[p1Ctr].allowEdit[0] + ',' + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowRead,' + p1[p1Ctr].allowRead[0] + ',' + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',ModifyAllRecords,' + p1[p1Ctr].modifyAllRecords[0] + ',' + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',ViewAllRecords,' + p1[p1Ctr].viewAllRecords[0] + ',' + '\n');;
        p1Ctr++;
        break;
      case p1[p1Ctr].object[0] > p2[p2Ctr].object[0]:
        fs.appendFileSync(f,"Object Permissions," + p2[p2Ctr].object[0] + ',AllowCreate,,' + p2[p2Ctr].allowCreate[0] + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p2[p2Ctr].object[0] + ',AllowDelete,,' + p2[p2Ctr].allowDelete[0] + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p2[p2Ctr].object[0] + ',AllowEdit,,' + p2[p2Ctr].allowEdit[0] + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p2[p2Ctr].object[0] + ',AllowRead,,' + p2[p2Ctr].allowRead[0] + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p2[p2Ctr].object[0] + ',ModifyAllRecords,,' + p2[p2Ctr].modifyAllRecords[0] + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p2[p2Ctr].object[0] + ',ViewAllRecords,,' + p2[p2Ctr].viewAllRecords[0] + '\n');;
        p2Ctr++;
        break;
      case program.report:
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowCreate,' + p1[p1Ctr].allowCreate[0] + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowDelete,' + p1[p1Ctr].allowDelete[0] + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowEdit,' + p1[p1Ctr].allowEdit[0] + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowRead,' + p1[p1Ctr].allowRead[0] + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',ModifyAllRecords,' + p1[p1Ctr].modifyAllRecords[0] + '\n');;
        fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',ViewAllRecords,' + p1[p1Ctr].viewAllRecords[0] + '\n');;
        p1Ctr++;
        p2Ctr++;
        break;
      default:
        if(program.same || p1[p1Ctr].allowCreate[0] !== p2[p2Ctr].allowCreate[0]){
          fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowCreate,' + p1[p1Ctr].allowCreate[0] + ',' + p2[p2Ctr].allowCreate[0] + '\n');
        }
        if(program.same || p1[p1Ctr].allowDelete[0] !== p2[p2Ctr].allowDelete[0]){
          fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowDelete,' + p1[p1Ctr].allowDelete[0] + ',' + p2[p2Ctr].allowDelete[0] + '\n');
        }
        if(program.same || p1[p1Ctr].allowEdit[0] !== p2[p2Ctr].allowEdit[0]){
          fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowEdit,' + p1[p1Ctr].allowEdit[0] + ',' + p2[p2Ctr].allowEdit[0] + '\n');
        }
        if(program.same || p1[p1Ctr].allowRead[0] !== p2[p2Ctr].allowRead[0]){
          fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',AllowRead,' + p1[p1Ctr].allowRead[0] + ',' + p2[p2Ctr].allowRead[0] + '\n');
        }
        if(program.same || p1[p1Ctr].modifyAllRecords[0] !== p2[p2Ctr].modifyAllRecords[0]){
          fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',ModifyAllRecords,' + p1[p1Ctr].modifyAllRecords[0] + ',' + p2[p2Ctr].modifyAllRecords[0] + '\n');
        }
        if(program.same || p1[p1Ctr].viewAllRecords[0] !== p2[p2Ctr].viewAllRecords[0]){
          fs.appendFileSync(f,"Object Permissions," + p1[p1Ctr].object[0] + ',ViewAllRecords,' + p1[p1Ctr].viewAllRecords[0] + ',' + p2[p2Ctr].viewAllRecords[0] + '\n');
        }
        p1Ctr++;
        p2Ctr++;
    }
  }

  return true;
}

/*
- apexPage
- enabled*/
function comparePageAccesses(f, p1, p2){
  if(p1 === p2 && !program.report){
    return false;
  }
  var p1Ctr = 0;
  var p2Ctr = 0;
  while(p1Ctr < p1.length && p2Ctr < p2.length){
    switch (true){
      case p1[p1Ctr].apexPage[0] < p2[p2Ctr].apexPage[0]:
        fs.appendFileSync(f,"Page Accesses," + p1[p1Ctr].apexPage[0] + ',Enabled,' + p1[p1Ctr].enabled[0] + ',' + '\n');;
        p1Ctr++;
        break;
      case p1[p1Ctr].apexPage[0] > p2[p2Ctr].apexPage[0]:
        fs.appendFileSync(f,"Page Accesses," + p2[p2Ctr].apexPage[0] + ',Enabled,,' + p2[p2Ctr].enabled[0] + '\n');;
        p2Ctr++;
        break;
      case program.report:
        fs.appendFileSync(f,"Page Accesses," + p1[p1Ctr].apexPage[0] + ',Enabled,' + p1[p1Ctr].enabled[0] + '\n');;
        p1Ctr++;
        p2Ctr++;
        break;
      default:
        if(program.same || p1[p1Ctr].enabled[0] !== p2[p2Ctr].enabled[0]){
          fs.appendFileSync(f,"Page Accesses," + p1[p1Ctr].apexPage[0] + ',Enabled,' + p1[p1Ctr].enabled[0] + ',' + p2[p2Ctr].enabled[0] + '\n');
        }
        p1Ctr++;
        p2Ctr++;
    }
  }

  return true;
}

/*
- recordType
- default
- visible*/
function compareRecordTypeVisibilities(f, p1, p2){
  if(p1 === p2 && !program.report){
    return false;
  }
  var p1Ctr = 0;
  var p2Ctr = 0;
  while(p1Ctr < p1.length && p2Ctr < p2.length){
    switch (true){
      case p1[p1Ctr].recordType[0] < p2[p2Ctr].recordType[0]:
        fs.appendFileSync(f,"Record Type Visibilities," + p1[p1Ctr].recordType[0] + ',Default,' + p1[p1Ctr].default[0] + ',' + '\n');;
        fs.appendFileSync(f,"Record Type Visibilities," + p1[p1Ctr].recordType[0] + ',Visibile,' + p1[p1Ctr].visible[0] + ',' + '\n');;
        p1Ctr++;
        break;
      case p1[p1Ctr].recordType[0] > p2[p2Ctr].recordType[0]:
        fs.appendFileSync(f,"Record Type Visibilities," + p2[p2Ctr].recordType[0] + ',Default,,' + p2[p2Ctr].default[0] + '\n');;
        fs.appendFileSync(f,"Record Type Visibilities," + p2[p2Ctr].recordType[0] + ',Visible,,' + p2[p2Ctr].visible[0] + '\n');;
        p2Ctr++;
        break;
      case program.report:
        fs.appendFileSync(f,"Record Type Visibilities," + p1[p1Ctr].recordType[0] + ',Default,' + p1[p1Ctr].default[0] + '\n');;
        fs.appendFileSync(f,"Record Type Visibilities," + p1[p1Ctr].recordType[0] + ',Visibile,' + p1[p1Ctr].visible[0] + '\n');;
        p1Ctr++;
        p2Ctr++;
        break;
      default:
        if(program.same || p1[p1Ctr].default[0] !== p2[p2Ctr].default[0]){
          fs.appendFileSync(f,"Record Type Visibilities," + p1[p1Ctr].recordType[0] + ',Default,' + p1[p1Ctr].default[0] + ',' + p2[p2Ctr].default[0] + '\n');
        }
        if(program.same || p1[p1Ctr].visible[0] !== p2[p2Ctr].visible[0]){
          fs.appendFileSync(f,"Record Type Visibilities," + p1[p1Ctr].recordType[0] + ',Visible,' + p1[p1Ctr].visible[0] + ',' + p2[p2Ctr].visible[0] + '\n');
        }
        p1Ctr++;
        p2Ctr++;
    }
  }

  return true;
}

/*
- tab
- visibility*/
function compareTabVisibilties(f, p1, p2){
  if(p1 === p2 && !program.report){
    return false;
  }
  var p1Ctr = 0;
  var p2Ctr = 0;
  while(p1Ctr < p1.length && p2Ctr < p2.length){
    switch (true){
      case p1[p1Ctr].tab[0] < p2[p2Ctr].tab[0]:
        fs.appendFileSync(f,"Tab Visibilities," + p1[p1Ctr].tab[0] + ',Visibility,' + p1[p1Ctr].visibility[0] + ',' + '\n');;
        p1Ctr++;
        break;
      case p1[p1Ctr].tab[0] > p2[p2Ctr].tab[0]:
        fs.appendFileSync(f,"Tab Visibilities," + p2[p2Ctr].tab[0] + ',Visibility,,' + p2[p2Ctr].visibility[0] + '\n');;
        p2Ctr++;
        break;
      case program.report:
        fs.appendFileSync(f,"Tab Visibilities," + p1[p1Ctr].tab[0] + ',Visibility,' + p1[p1Ctr].visibility[0] + '\n');;
        p1Ctr++;
        p2Ctr++;
        break;
      default:
        if(program.same || p1[p1Ctr].visibility[0] !== p2[p2Ctr].visibility[0]){
          fs.appendFileSync(f,"Tab Visibilities," + p1[p1Ctr].tab[0] + ',Visibility,' + p1[p1Ctr].visibility[0] + ',' + p2[p2Ctr].visibility[0] + '\n');
        }
        p1Ctr++;
        p2Ctr++;
    }
  }

  return true;
}

function compareUserLicense(f, p1, p2){
  if(p1 && p2 && p1[0] === p2[0] && !program.report){
    return false;
  }
  fs.appendFileSync(f,'User License,,,' + p1  + '\n');;

  return true;
}

/*
- name
- enabled*/
function compareUserPermissions(f, p1, p2){
  if(p1 === p2 && !program.report){
    return false;
  }
  var p1Ctr = 0;
  var p2Ctr = 0;
  while(p1Ctr < p1.length && p2Ctr < p2.length){
    switch (true){
      case p1[p1Ctr].name[0] < p2[p2Ctr].name[0]:
        fs.appendFileSync(f,"User Permissions," + p1[p1Ctr].name[0] + ',Enabled,' + p1[p1Ctr].enabled[0] + ',' + '\n');;
        p1Ctr++;
        break;
      case p1[p1Ctr].name[0] > p2[p2Ctr].name[0]:
        fs.appendFileSync(f,"User Permissions," + p2[p2Ctr].name[0] + ',Enabled,,' + p2[p2Ctr].enabled[0] + '\n');;
        p2Ctr++;
        break;
      case program.report:
        fs.appendFileSync(f,"User Permissions," + p1[p1Ctr].name[0] + ',Enabled,' + p1[p1Ctr].enabled[0] + '\n');;
        p1Ctr++;
        p2Ctr++;
        break;
      default:
        if(program.same || p1[p1Ctr].enabled[0] !== p2[p2Ctr].enabled[0]){
          fs.appendFileSync(f,"User Permissions," + p1[p1Ctr].name[0] + ',Enabled,' + p1[p1Ctr].enabled[0] + ',' + p2[p2Ctr].enabled[0] + '\n');
        }
        p1Ctr++;
        p2Ctr++;
    }
  }

  return true;
}
