//
// Created by russ on 23-10-19.
//

#ifndef MOSQUITTO_MESSAGE_ENCRYPT_GRAPH_HPP
#define MOSQUITTO_MESSAGE_ENCRYPT_GRAPH_HPP
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/iteration_macros.hpp>
#include <boost/graph/graphviz.hpp>
#include <utility>
#include <filesystem>
#include <cairo/cairo.h>
#include <mongocxx/uri.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>

namespace Graph{
    struct vertex_info {
        std::string name;
        time_t timestamp{};
    };

    typedef boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS,vertex_info> graph;

    class Graph {
    public:
        explicit Graph():p(nullptr){};
        explicit Graph(const std::string& _owner,mongocxx::pool *_p);
        explicit Graph(const graph& _g,std::string  _owner,mongocxx::pool *_p):g(_g),owner(std::move(_owner)),p(_p){};
        Graph(const Graph& _g);
        ~Graph();
        graph::vertex_descriptor add_vertex(const std::string &name);
        void set_owner(const std::string &name);
        graph get_graph();
        std::string get_owner();
        std::string get_vertex_name(const graph::vertex_descriptor &v);
        void visualization(const std::string &filename);
        void store(mongocxx::pool *pool);
        void load(mongocxx::pool *pool);
        void update(mongocxx::pool *pool);
        void add_edge(graph::vertex_descriptor source,graph::vertex_descriptor target);
        unsigned long size();
    private:
        graph g;
        std::string owner;
        time_t timestamp{};
        mongocxx::pool *p;
    };


    Graph::Graph(const Graph &_g) {
        this->g = _g.g;
        this->owner = _g.owner;
        this->timestamp = _g.timestamp;
        this->p = _g.p;
    }

    graph::vertex_descriptor Graph::add_vertex(const std::string &name) {
        vertex_info v_info;
        // 设置节点名称
        v_info.name = name;
        // 设置节点时间戳
        v_info.timestamp = time(nullptr);
        return boost::add_vertex(v_info,this->g);
    }

    void Graph::set_owner(const std::string &name) {
        this->owner = name;
    }

    Graph::Graph(const std::string& _owner,mongocxx::pool *_p):owner(_owner),p(_p) {
        this->timestamp = time(nullptr);
        auto client = this->p->try_acquire();
        if (!client) {
            fprintf(stderr, "Failed to pop client from pool.\n");
            return;
        }
        auto graph_collection = (*client)->database("mqtt").collection("graph");
        if (!graph_collection) {
            fprintf(stderr, "Failed to get collection.\n");
            return;
        }
        bsoncxx::builder::stream::document filter_builder;
        filter_builder << "owner" << this->owner;
        filter_builder << "timestamp" << bsoncxx::types::b_date{std::chrono::system_clock::from_time_t(this->timestamp)};
        if (graph_collection.count_documents(filter_builder.view()) <= 0){
            bsoncxx::builder::stream::document doc_builder;
            doc_builder << "owner" << this->owner;
            doc_builder << "timestamp" << bsoncxx::types::b_date{std::chrono::system_clock::from_time_t(this->timestamp)};
            doc_builder << "edges" << bsoncxx::builder::stream::open_array << bsoncxx::builder::stream::close_array;
            graph_collection.insert_one(doc_builder.view());
            std::cout << "插入新的文档成功。" << std::endl;
            return;
        }
    }

    void Graph::add_edge(graph::vertex_descriptor source,graph::vertex_descriptor target){
        auto result = boost::add_edge(source,target,this->g);
        auto client = this->p->try_acquire();
        if (!client) {
            fprintf(stderr, "Failed to pop client from pool.\n");
            return;
        }
        auto graph_collection = (*client)->database("mqtt").collection("graph");
        if (!graph_collection) {
            fprintf(stderr, "Failed to get collection.\n");
            return;
        }
        if (result.second){
            auto _source = boost::source(result.first, this->g);
            auto _target = boost::target(result.first, this->g);
            bsoncxx::builder::basic::document doc;
            doc.append(bsoncxx::builder::basic::kvp("source_vertex_name",this->g[_source].name));
            doc.append(bsoncxx::builder::basic::kvp("source_vertex_time",bsoncxx::types::b_date{std::chrono::system_clock::from_time_t(this->g[_source].timestamp)}));
            doc.append(bsoncxx::builder::basic::kvp("target_vertex_name",this->g[_target].name));
            doc.append(bsoncxx::builder::basic::kvp("target_vertex_time",bsoncxx::types::b_date{std::chrono::system_clock::from_time_t(this->g[_target].timestamp)}));
            bsoncxx::builder::stream::document filter_builder;
            filter_builder << "owner" << this->owner;
            filter_builder << "timestamp" << bsoncxx::types::b_date{std::chrono::system_clock::from_time_t(this->timestamp)};
            if (graph_collection.count_documents(filter_builder.view()) <= 0){
                bsoncxx::builder::stream::document doc_builder;
                doc_builder << "owner" << this->owner;
                doc_builder << "timestamp" << bsoncxx::types::b_date{std::chrono::system_clock::from_time_t(this->timestamp)};
                doc_builder << "edges" << bsoncxx::builder::stream::open_array << doc << bsoncxx::builder::stream::close_array;
                graph_collection.insert_one(doc_builder.view());
                std::cout << "插入新的文档成功。" << std::endl;
                return;
            }
            bsoncxx::builder::stream::document update_builder;
            update_builder << "$push" << bsoncxx::builder::stream::open_document <<
                     "edges" << doc << bsoncxx::builder::stream::close_document;
            auto result = graph_collection.update_one(filter_builder.view(),update_builder.view());
            if (result) {
                if (result->modified_count() > 0) {
                    std::cout << "数组字段更新成功。" << std::endl;
                } else {
                    std::cout << "没有匹配的文档需要更新。" << std::endl;
                }
            } else {
                std::cerr << "更新操作失败。" << std::endl;
            }
        }
    }
    std::string Graph::get_owner() {
        return this->owner;
    }

    std::string Graph::get_vertex_name(const graph::vertex_descriptor &v) {
        return this->g[v].name;
    }

    void Graph::visualization(const std::string &filename) {
        if (filename.empty()){
            fprintf(stderr,"No Such Path\n");
            return;
        }
        std::ofstream file(filename);
        boost::write_graphviz(file,this->g,boost::make_label_writer(boost::get(&vertex_info::name,this->g)));
        system(("dot -Tpng " + filename + " -o " + filename + ".png").c_str());
        file.close();
    }

    void Graph::store(mongocxx::pool *pool) {
        auto client = pool->try_acquire();
        if (!client) {
            fprintf(stderr, "Failed to pop client from pool.\n");
            return;
        }
        auto graph_collection = (*client)->database("mqtt").collection("graph");
        if (!graph_collection) {
            fprintf(stderr, "Failed to get collection.\n");
            return;
        }
        auto doc_builder = bsoncxx::builder::basic::document{};
        auto vertexs = bsoncxx::builder::basic::array{};
        doc_builder.append(bsoncxx::builder::basic::kvp("owner",this->owner));
        doc_builder.append(bsoncxx::builder::basic::kvp("timestamp",bsoncxx::types::b_date{std::chrono::system_clock::now()}));
        graph_collection.insert_one(doc_builder.view());
    }

    void Graph::load(mongocxx::pool *pool) {
        auto client = pool->try_acquire();
        if (!client) {
            fprintf(stderr, "Failed to pop client from pool.\n");
            return;
        }
        auto graph_collection = (*client)->database("mqtt").collection("graph");
        if (!graph_collection) {
            fprintf(stderr, "Failed to get collection.\n");
            return;
        }
        auto doc = bsoncxx::builder::stream::document{};
        doc << "owner" << this->owner;
        doc << "timestamp" << bsoncxx::types::b_date{std::chrono::system_clock::from_time_t(this->timestamp)};
        auto cursor = graph_collection.find_one(doc.view());
        if (!cursor) {
            fprintf(stderr, "No Such Graph:%s\n",this->owner.c_str());
            return;
        }
        auto element = cursor->view()["edges"];
        if (!element) {
            fprintf(stderr, "No Such Graph:%s\n",this->owner.c_str());
            return;
        }
        auto array = element.get_array().value;
        for (const auto &item: array){
            auto source_vertex_name = item["source_vertex_name"].get_string().value.to_string();
            auto source_vertex_time = item["source_vertex_time"].get_date();
            auto target_vertex_name = item["target_vertex_name"].get_string().value.to_string();
            auto target_vertex_time = item["target_vertex_time"].get_date();
            auto source_vertex = this->add_vertex(source_vertex_name);
            auto target_vertex = this->add_vertex(target_vertex_name);
            this->add_edge(source_vertex,target_vertex);
            this->g[source_vertex].timestamp = std::chrono::system_clock::to_time_t(source_vertex_time);
            this->g[target_vertex].timestamp = std::chrono::system_clock::to_time_t(target_vertex_time);
        }
    }

    Graph::~Graph() {
        g.clear();
    }

    graph Graph::get_graph() {
        return this->g;
    }

    unsigned long Graph::size() {
        return boost::num_vertices(this->g);
    }

    void Graph::update(mongocxx::pool *pool) {
        auto client = pool->try_acquire();
        if (!client) {
            fprintf(stderr, "Failed to pop client from pool.\n");
            return;
        }
        auto graph_collection = (*client)->database("mqtt").collection("graph");
        if (!graph_collection) {
            fprintf(stderr, "Failed to get collection.\n");
            return;
        }
        auto doc_builder = bsoncxx::builder::basic::document{};
        auto update_builder = bsoncxx::builder::stream::document{};
        doc_builder.append(bsoncxx::builder::basic::kvp("owner",this->owner));

    }

}


#endif //MOSQUITTO_MESSAGE_ENCRYPT_GRAPH_HPP
