#ifndef _AVL_TREE_HEADER_H
#define _AVL_TREE_HEADER_H

#include <Windows.h>

#define ROOT_ELEMENT_OF_TREE(Tree) ((Tree)->Root.Right)

typedef enum _tree_enum_order
{
    tree_enum_order_in_order,
    tree_enum_order_reverse_order
} tree_enum_order;

typedef struct _st_avl_nodes
{
    struct _st_avl_nodes *Parent;
    struct _st_avl_nodes *Left;
    struct _st_avl_nodes *Right;
    LONG Balance;
} st_avl_nodes, *pst_avl_nodes;

typedef LONG ( *func_avl_tree_compare)(
    _In_ pst_avl_nodes Links1,
    _In_ pst_avl_nodes Links2
    );

typedef struct _st_avl_tree
{
    st_avl_nodes			Root; 
    ULONG					Count;
    func_avl_tree_compare	CompareFunction;
} st_avl_tree, *pst_avl_tree;

typedef BOOLEAN ( *func_avl_tree_enum_callback)(
    _In_ pst_avl_tree Tree,
    _In_ pst_avl_nodes Element,
    _In_opt_ PVOID Context
    );

VOID avl_tree_init(
    _Out_ pst_avl_tree Tree,
    _In_ func_avl_tree_compare CompareFunction
    );


pst_avl_nodes avl_tree_add_node(
    _Inout_ pst_avl_tree Tree,
    _Out_ pst_avl_nodes Element
    );

VOID avl_tree_remove_node(
    _Inout_ pst_avl_tree Tree,
    _Inout_ pst_avl_nodes Element
    );

pst_avl_nodes avl_tree_find_node(
    _In_ pst_avl_tree Tree,
    _In_ pst_avl_nodes Element
    );

pst_avl_nodes avl_tree_find_closest_node(
    _In_ pst_avl_tree Tree,
    _In_ pst_avl_nodes Element,
    _Out_ PLONG Result
    );

pst_avl_nodes avl_tree_minimum_node(
    _In_ pst_avl_tree Tree
    );

pst_avl_nodes avl_tree_maximum_node(
    _In_ pst_avl_tree Tree
    );

pst_avl_nodes avl_tree_successor_node(
    _In_ pst_avl_nodes Element
    );

pst_avl_nodes avl_tree_predecessor_node(
    _In_ pst_avl_nodes Element
    );

VOID avl_tree_enum(
    _In_ pst_avl_tree Tree,
    _In_ tree_enum_order Order,
    _In_ func_avl_tree_enum_callback Callback,
    _In_opt_ PVOID Context
    );
#endif
