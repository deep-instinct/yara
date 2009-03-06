/*

Copyright(c) 2008. Victor M. Alvarez [plusvic@gmail.com].

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

*/

/* headers */

#include <Python.h>
#include "structmember.h"

#include "yara.h"

/* Module globals */

static PyObject *YaraError = NULL;
static PyObject *YaraSyntaxError = NULL;


static char* module_doc = "\
This module allows you to apply YARA rules to files or strings.               \n\
                                                                              \n\
First of all your need to compile your YARA rules. The method \"compile\" can \n\
receive a file path, a file object, or a string containing the rules.         \n\
                                                                              \n\
rules = yara.compile(filepath='/foo/bar/myrules')                             \n\
rules = yara.compile('/foo/bar/myrules')                                      \n\
                                                                              \n\
f = open('/foo/bar/myrules')                                                  \n\
rules = yara.compile(file=f)                                                  \n\
f.close()                                                                     \n\
                                                                              \n\
rules = yara.compile(source='rule dummy { condition: true }')                 \n\
                                                                              \n\
This method returns an instance of the \"Rules\" class if the rules were      \n\
compiled sucessfully, or raises an exception in other case.                   \n\
                                                                              \n\
The returned \"Rules\" object has a method \"match\" that allows you to apply \n\
the rules to your data. This method can receive a file path or a string       \n\
containing the data.                                                          \n\
                                                                              \n\
matches = rules.match(filepath='/foo/bar/myfile')                             \n\
                                                                              \n\
matches = rules.match('/foo/bar/myfile')                                      \n\
                                                                              \n\
f = fopen('/foo/bar/myfile', 'rb')                                            \n\
matches = rules.match(data=f.read())                                          \n\
                                                                              \n\
The \"match\" method returns a list of instances of the class \"Match\". The  \n\
instances of this class can be treated as text string containing the name of  \n\
the matching YARA rule.                                                       \n\
                                                                              \n\
For example you can print them:                                               \n\
                                                                              \n\
foreach m in matches:                                                         \n\
    print \"%s\" % m                                                          \n\
                                                                              \n\
In some circumstances you may need to explicitly convert the instance of      \n\
\"Match\" to string, for example when comparing it with another string:       \n\
                                                                              \n\
if str(matches[0]) == 'SomeRuleName':                                         \n\
    ...                                                                       \n\
                                                                              \n\
The \"Match\" class have another two attributes: \"tags\" and \"strings\". The\n\
\"tags\" attribute is a list of strings containing the tags associated to the \n\
rule. The \"strings\" attribute is a dictionary whose values are those strings\n\
within the data that made the YARA rule match, and the keys are the offset    \n\
where the associated string was found.                                        \n";



//////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    
    PyObject_HEAD
    char* rule;
    PyObject* tags;
    PyObject* strings;

} Match;

static PyObject * Match_Repr(PyObject *self);
static PyObject * Match_getattro(PyObject *self, PyObject *name);
static void Match_dealloc(PyObject *self);

static PyMemberDef Match_members[] = {
    {"tags", T_OBJECT_EX, offsetof(Match, tags), READONLY, "List of tags associated to the rule"},
    {"strings", T_OBJECT_EX, offsetof(Match, strings), READONLY, "Dictionary with offsets and strings that matched the file"},
    {NULL}  /* Sentinel */
};

static PyMethodDef Match_methods[] = 
{
    {NULL},
};

static PyTypeObject Match_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "yara.Match",               /*tp_name*/
    sizeof(Match),              /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    (destructor)Match_dealloc,  /*tp_dealloc*/
    0,                          /*tp_print*/
    0,                          /*tp_getattr*/
    0,                          /*tp_setattr*/
    0,                          /*tp_compare*/
    Match_Repr,                 /*tp_repr*/
    0,                          /*tp_as_number*/
    0,                          /*tp_as_sequence*/
    0,                          /*tp_as_mapping*/
    0,                          /*tp_hash */
    0,                          /*tp_call*/
    0,                          /*tp_str*/
    Match_getattro,     /*tp_getattro*/
    0,                          /*tp_setattro*/
    0,                          /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Match class",              /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    Match_methods,              /* tp_methods */
    Match_members,              /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    0,                          /* tp_alloc */
    0,                          /* tp_new */
};


static PyObject * Match_NEW(char* rule, PyObject* tags, PyObject* strings)
{ 
    Match* object;
    
    object = PyObject_NEW(Match, &Match_Type);
    
    if (object != NULL)
    {
        object->rule = rule;   
        object->tags = tags;
        object->strings = strings;
    } 
      
    return (PyObject *)object;
}

static void Match_dealloc(PyObject *self)
{    
    Match *object = (Match *) self;
     
    Py_DECREF(object->tags); 
    Py_DECREF(object->strings);
    PyObject_Del(self);
}

static PyObject * Match_Repr(PyObject *self)
{ 
    Match *object = (Match *) self;
    
    return PyString_FromString(object->rule);
}

static PyObject * Match_getattro(PyObject *self, PyObject *name)
{
    return PyObject_GenericGetAttr(self, name); 
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    
    PyObject_HEAD
    RULE_LIST* rules;

} Rules;


static PyObject * Rules_match(PyObject *self, PyObject *args, PyObject *keywords);
static PyObject * Rules_getattro(PyObject *self, PyObject *name);
static void Rules_dealloc(PyObject *self);

static PyMethodDef Rules_methods[] = 
{
  {"match", (PyCFunction) Rules_match, METH_VARARGS | METH_KEYWORDS},
  {NULL, NULL},
};

static PyTypeObject Rules_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "yara.Rules",               /*tp_name*/
    sizeof(Rules),              /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    (destructor)Rules_dealloc,  /*tp_dealloc*/
    0,                          /*tp_print*/
    0,                          /*tp_getattr*/
    0,                          /*tp_setattr*/
    0,                          /*tp_compare*/
    0,                          /*tp_repr*/
    0,                          /*tp_as_number*/
    0,                          /*tp_as_sequence*/
    0,                          /*tp_as_mapping*/
    0,                          /*tp_hash */
    0,                          /*tp_call*/
    0,                          /*tp_str*/
    Rules_getattro,             /*tp_getattro*/
    0,                          /*tp_setattro*/
    0,                          /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Rules class",              /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    Rules_methods,              /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    0,                          /* tp_alloc */
    0,                          /* tp_new */
};


//////////////////////////////////////////////////////////////////////////////////////////////////////////

static PyObject * Rules_NEW(FILE* file)
{ 
    RULE_LIST* rules;
    Rules* object;
    int errors;

    rules = alloc_rule_list();
    
    if (rules == NULL)
    {
        return PyErr_NoMemory();
    }
    
    if (file == NULL)
    {
        free_rule_list(rules);
        return PyErr_SetFromErrno(PyExc_IOError);
    }
        
    errors = compile_rules(file, rules);
       
    if (errors > 0)   /* errors during compilation */
    {
        free_rule_list(rules);       
        return PyErr_Format(YaraSyntaxError, "line %d: %s", get_error_line_number(), get_last_error_message());
    }
    
    object = PyObject_NEW(Rules, &Rules_Type);
    
    if (object != NULL)
    {
        init_hash_table(rules);   
        object->rules = rules;
    } 
      
    return (PyObject *)object;
}

static void Rules_dealloc(PyObject *self)
{     
    free_hash_table(((Rules*) self)->rules);
    free_rule_list(((Rules*) self)->rules);
    PyObject_Del(self);
}

int callback(RULE* rule, unsigned char* buffer, unsigned int buffer_size, void* data)
{
    TAG* tag;
    STRING* string;
    MATCH* m;
    PyObject* taglist = NULL;
    PyObject* stringlist = NULL;
    PyObject* match;
    PyObject* list = (PyObject*) data;
    
    if (!(rule->flags & RULE_FLAGS_MATCH))
        return 0;
       
    taglist = PyList_New(0);
    stringlist = PyDict_New();
    
    if (taglist == NULL || stringlist == NULL)
        return 1; // error!
        
    tag = rule->tag_list_head;
    
    while(tag != NULL)
    {
        PyList_Append(taglist, PyString_FromString(tag->identifier));               
        tag = tag->next;
    }       
    
    string = rule->string_list_head;

    while (string != NULL)
    {
        if (string->flags & STRING_FLAGS_FOUND)
        {
            m = string->matches;

            while (m != NULL)
            {
                PyDict_SetItem( stringlist,
                                PyInt_FromLong(m->offset),
                                PyString_FromStringAndSize((char*) buffer + m->offset, m->length));
                m = m->next;
            }
        }

        string = string->next;
    }
       
    match = Match_NEW(rule->identifier, taglist, stringlist);
    
    if (match != NULL)
    {       
        PyList_Append(list, match);
    }
    else
    {
        Py_DECREF(taglist);
        Py_DECREF(stringlist);
        return 1;
    }
    
    return 0;

}

PyObject * Rules_match(PyObject *self, PyObject *args, PyObject *keywords)
{
    static char *kwlist[] = {"filepath", "data", NULL};
    
    char* filepath = NULL;
    char* data = NULL;
    
    int length;
    int result;
    
    PyObject *matches = NULL;
    Rules *object = (Rules *)self;
    
    if (PyArg_ParseTupleAndKeywords(args, keywords, "|ss#", kwlist, &filepath, &data, &length))
    {
        matches = PyList_New(0);
        
        if (filepath != NULL)
        {            
            result = scan_file(filepath, object->rules, callback, matches);

            if (result != ERROR_SUCCESS)
            {
                Py_DECREF(matches);

                switch(result)
                {
                    case ERROR_COULD_NOT_OPEN_FILE:
                        return PyErr_Format(YaraError, "could not open file \"%s\"", filepath);
                    case ERROR_COULD_NOT_MAP_FILE:
                        return PyErr_Format(YaraError, "could not map file \"%s\" into memory", filepath);
                    case ERROR_ZERO_LENGTH_FILE:
                        return PyErr_Format(YaraError, "zero length file \"%s\"", filepath);
                    default:
                        return PyErr_Format(YaraError, "uknown error while scanning file \"%s\"", filepath);
                }
            }
        }
        else if (data != NULL)
        {
            result = scan_mem((unsigned char*) data, (unsigned int) length, object->rules, callback, matches);

            if (result != ERROR_SUCCESS)
            {
               Py_DECREF(matches);
               return PyErr_Format(PyExc_Exception, "internal error"); 
            }
        }
        else
        {
            return PyErr_Format(PyExc_TypeError, "match() takes 1 argument");
        }
    }
    
    return matches;
}

static PyObject * Rules_getattro(PyObject *self, PyObject *name)
{
    return PyObject_GenericGetAttr(self, name); 
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

static PyObject * yara_compile(PyObject *self, PyObject *args, PyObject *keywords)
{ 
    static char *kwlist[] = {"filepath", "source", "file", NULL};
    
    FILE* fh;
    
    PyObject *result = NULL;
    PyObject *py_file = NULL;

    char* filepath = NULL;
    char* source = NULL;
    
    if (PyArg_ParseTupleAndKeywords(args, keywords, "|ssO", kwlist, &filepath, &source, &py_file))
    {
        if (filepath != NULL)
        {            
            fh = fopen(filepath, "r");
            
            if (fh != NULL)
            {
                result = Rules_NEW(fh);
                fclose(fh);
            }
            else
            {
                result = PyErr_SetFromErrno(YaraError);
            }
        }
        else if (source != NULL)
        {
            fh = tmpfile();
            
            if (fh != NULL)
            {
                fprintf(fh, "%s", source);
                fseek(fh, 0, SEEK_SET);
            
                result = Rules_NEW(fh);
            
                fclose(fh);
            }
            else
            {
                result = PyErr_SetFromErrno(YaraError);
            }
        }
        else if (py_file != NULL)
        {
            fh = PyFile_AsFile(py_file);   
            result = Rules_NEW(fh);
        }
        else
        {
            result = PyErr_Format(PyExc_TypeError, "compile() takes 1 argument");
        }
    } 

      
    return result;
}

/* Module functions */

static PyMethodDef methods[] = {
  {"compile", (PyCFunction) yara_compile, METH_VARARGS | METH_KEYWORDS, "Compiles a YARA rules file and returns an instance of class Rules"},
  {NULL, NULL},
};

/* Module init function */

void inityara(void)
{ 
    PyObject *m, *d;
 
    m = Py_InitModule3("yara", methods, module_doc);
    d = PyModule_GetDict(m);
    
    /* initialize module variables/constants */

#if PYTHON_API_VERSION >= 1007
    YaraError = PyErr_NewException("yara.Error", PyExc_StandardError, NULL);
    YaraSyntaxError = PyErr_NewException("yara.SyntaxError", YaraError, NULL);
#else
    YaraError = Py_BuildValue("s", "yara.Error");
    YaraSyntaxError = Py_BuildValue("s", "yara.SyntaxError");
#endif
    PyDict_SetItemString(d, "Error", YaraError);
    PyDict_SetItemString(d, "SyntaxError", YaraSyntaxError);
}
